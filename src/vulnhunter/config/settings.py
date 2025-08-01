"""Configuration settings for VulnHunter using Pydantic."""

from typing import Dict, List, Optional, Set
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AnalysisLayer(str, Enum):
    """Available analysis layers."""
    
    STATIC = "static"
    FUZZING = "fuzzing"
    SYMBOLIC = "symbolic"
    FORMAL = "formal"
    AI = "ai"
    ALL = "all"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolConfig(BaseModel):
    """Configuration for individual analysis tools."""
    
    enabled: bool = True
    timeout: int = Field(default=300, description="Tool timeout in seconds")
    max_memory_mb: int = Field(default=4096, description="Maximum memory usage in MB")
    docker_image: Optional[str] = None
    extra_args: Dict[str, str] = Field(default_factory=dict)


class AnalysisConfig(BaseModel):
    """Configuration for a single analysis run."""
    
    # Analysis options
    layers: Set[AnalysisLayer] = Field(
        default={AnalysisLayer.STATIC, AnalysisLayer.FUZZING},
        description="Which analysis layers to run"
    )
    tools: Optional[List[str]] = Field(
        default=None,
        description="Specific tools to run (None = all available)"
    )
    
    # Performance options
    parallel_tools: bool = Field(default=True, description="Run tools in parallel")
    cache_results: bool = Field(default=True, description="Cache analysis results")
    early_exit_on_critical: bool = Field(
        default=False,
        description="Stop analysis if critical vulnerability found"
    )
    
    # Output options
    generate_poc: bool = Field(default=True, description="Generate proof-of-concept exploits")
    output_format: str = Field(default="json", description="Output format (json, sarif)")
    min_severity: SeverityLevel = Field(
        default=SeverityLevel.LOW,
        description="Minimum severity to report"
    )
    
    # Resource limits
    max_analysis_time: int = Field(default=1800, description="Maximum total analysis time")
    max_contract_size_mb: int = Field(default=1, description="Maximum contract size in MB")
    

class Settings(BaseSettings):
    """Global application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="VULNHUNTER_",
        case_sensitive=False,
    )
    
    # API Keys
    etherscan_api_key: Optional[str] = Field(default=None, description="Etherscan API key")
    
    # Paths
    project_root: Path = Field(default=Path.cwd(), description="Project root directory")
    cache_dir: Path = Field(default=Path(".vulnhunter_cache"), description="Cache directory")
    results_dir: Path = Field(default=Path("results"), description="Results output directory")
    temp_dir: Path = Field(default=Path("/tmp/vulnhunter"), description="Temporary files")
    
    # Docker settings
    docker_network: str = Field(default="vulnhunter_net", description="Docker network name")
    use_gpu: bool = Field(default=False, description="Enable GPU acceleration")
    
    # Tool configurations
    tools: Dict[str, ToolConfig] = Field(
        default_factory=lambda: {
            "slither": ToolConfig(
                docker_image="trailofbits/eth-security-toolbox",
                timeout=300,
            ),
            "mythril": ToolConfig(
                docker_image="mythril/myth:latest",
                timeout=600,
                max_memory_mb=8192,
            ),
            "echidna": ToolConfig(
                docker_image="trailofbits/echidna:latest",
                timeout=900,
                extra_args={"test-limit": "50000"},
            ),
            "manticore": ToolConfig(
                docker_image="trailofbits/manticore:latest",
                timeout=1200,
                max_memory_mb=16384,
            ),
            "medusa": ToolConfig(
                docker_image="trailofbits/medusa:latest",
                timeout=600,
            ),
            "halmos": ToolConfig(
                docker_image="a16z/halmos:latest",
                timeout=600,
            ),
            "aderyn": ToolConfig(
                enabled=True,
                timeout=300,
            ),
            "foundry": ToolConfig(
                docker_image="ghcr.io/foundry-rs/foundry:latest",
                timeout=600,
            ),
        }
    )
    
    # SWC Registry settings
    swc_registry_url: str = Field(
        default="https://swcregistry.io/api/v1/",
        description="SWC Registry API URL"
    )
    swc_cache_ttl: int = Field(default=86400, description="SWC cache TTL in seconds")
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format (json, text)")
    
    # Performance
    max_workers: int = Field(default=4, description="Maximum parallel workers")
    worker_timeout: int = Field(default=3600, description="Worker timeout in seconds")
    
    @validator("cache_dir", "results_dir", "temp_dir", pre=True)
    def resolve_paths(cls, v: Path, values: dict) -> Path:
        """Resolve paths relative to project root."""
        if isinstance(v, str):
            v = Path(v)
        if not v.is_absolute() and "project_root" in values:
            return values["project_root"] / v
        return v
    
    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Get configuration for a specific tool."""
        return self.tools.get(tool_name, ToolConfig())
    
    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        for dir_path in [self.cache_dir, self.results_dir, self.temp_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)