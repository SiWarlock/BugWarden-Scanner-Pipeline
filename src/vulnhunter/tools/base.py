"""Base classes for tool wrappers."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from vulnhunter.models.vulnerability import Finding, SeverityLevel


class ToolStatus(str, Enum):
    """Status of tool execution."""
    
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ToolResult:
    """Result from a tool execution."""
    
    tool_name: str
    status: ToolStatus
    findings: List[Finding]
    execution_time: float
    raw_output: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ToolWrapper(ABC):
    """Abstract base class for all tool wrappers."""
    
    def __init__(self, tool_name: str, config: Optional[Dict[str, Any]] = None):
        """Initialize tool wrapper.
        
        Args:
            tool_name: Name of the tool
            config: Tool-specific configuration
        """
        self.tool_name = tool_name
        self.config = config or {}
        self._initialized = False
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the tool (pull images, check dependencies, etc.)."""
        pass
    
    @abstractmethod
    async def analyze(self, contract_path: Path) -> ToolResult:
        """Analyze a contract and return findings.
        
        Args:
            contract_path: Path to contract file or directory
            
        Returns:
            ToolResult with findings and execution details
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources (stop containers, remove temp files, etc.)."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is available and ready to use."""
        pass
    
    def parse_severity(self, severity_str: str) -> SeverityLevel:
        """Parse tool-specific severity to standard SeverityLevel.
        
        Args:
            severity_str: Tool-specific severity string
            
        Returns:
            Standardized SeverityLevel
        """
        # Default mapping - tools can override
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO,
            "warning": SeverityLevel.MEDIUM,
        }
        
        return severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()