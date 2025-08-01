"""Smart contract data models."""

from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from hashlib import sha256

from pydantic import BaseModel, Field, validator


class ContractSource(BaseModel):
    """Source code information for a contract."""
    
    file_path: str
    content: str
    compiler_version: Optional[str] = None
    optimization_enabled: Optional[bool] = None
    optimization_runs: Optional[int] = None
    
    @property
    def content_hash(self) -> str:
        """Get SHA256 hash of content for caching."""
        return sha256(self.content.encode()).hexdigest()
    

class Contract(BaseModel):
    """Smart contract information."""
    
    # Identification
    address: Optional[str] = Field(None, description="On-chain address if deployed")
    name: str
    
    # Source information
    sources: List[ContractSource] = Field(default_factory=list)
    main_source: Optional[ContractSource] = None
    imports: List[str] = Field(default_factory=list)
    
    # Compilation info
    solidity_version: Optional[str] = None
    evm_version: Optional[str] = Field(default="paris")
    optimization: bool = False
    runs: int = 200
    
    # Contract metadata
    is_abstract: bool = False
    is_interface: bool = False
    is_library: bool = False
    inherits_from: List[str] = Field(default_factory=list)
    
    # Bytecode
    bytecode: Optional[str] = None
    deployed_bytecode: Optional[str] = None
    source_map: Optional[str] = None
    
    # ABI and functions
    abi: Optional[List[Dict[str, Any]]] = None
    functions: List[str] = Field(default_factory=list)
    modifiers: List[str] = Field(default_factory=list)
    events: List[str] = Field(default_factory=list)
    
    # Multi-contract context
    dependencies: List[str] = Field(default_factory=list, description="Other contracts this depends on")
    external_calls: List[str] = Field(default_factory=list, description="External contracts called")
    
    # Analysis metadata
    analyzed_at: Optional[datetime] = None
    analysis_hash: Optional[str] = None
    
    @validator("address")
    def validate_address(cls, v: Optional[str]) -> Optional[str]:
        """Validate Ethereum address format."""
        if v is None:
            return v
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid Ethereum address format")
        return v.lower()
    
    @property
    def content_hash(self) -> str:
        """Get combined hash of all source contents."""
        combined = "".join(s.content_hash for s in self.sources)
        return sha256(combined.encode()).hexdigest()
    
    @property
    def is_multi_file(self) -> bool:
        """Check if contract spans multiple files."""
        return len(self.sources) > 1
    
    def get_function_signatures(self) -> List[str]:
        """Extract function signatures from ABI."""
        if not self.abi:
            return []
        
        signatures = []
        for item in self.abi:
            if item.get("type") == "function":
                name = item["name"]
                inputs = ",".join(inp["type"] for inp in item.get("inputs", []))
                signatures.append(f"{name}({inputs})")
        
        return signatures
    
    def has_external_calls(self) -> bool:
        """Check if contract makes external calls."""
        return len(self.external_calls) > 0
    
    def has_payable_functions(self) -> bool:
        """Check if contract has payable functions."""
        if not self.abi:
            return False
        
        return any(
            item.get("stateMutability") == "payable"
            for item in self.abi
            if item.get("type") == "function"
        )