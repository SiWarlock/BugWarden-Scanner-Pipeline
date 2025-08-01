"""Analysis report data models."""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from vulnhunter.models.vulnerability import Vulnerability, ValidatedExploit
from vulnhunter.models.contract import Contract
from vulnhunter.config.settings import SeverityLevel


class AnalysisStatus(str, Enum):
    """Status of analysis run."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ToolResult(BaseModel):
    """Result from a single analysis tool."""
    
    tool_name: str
    status: AnalysisStatus
    duration: Optional[timedelta] = None
    findings_count: int = 0
    error: Optional[str] = None
    raw_output: Optional[str] = None
    

class AnalysisMetrics(BaseModel):
    """Metrics and statistics for the analysis."""
    
    total_vulnerabilities: int = 0
    by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict)
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_swc: Dict[str, int] = Field(default_factory=dict)
    
    # Performance metrics
    total_duration: Optional[timedelta] = None
    tool_durations: Dict[str, timedelta] = Field(default_factory=dict)
    
    # Coverage metrics
    functions_analyzed: int = 0
    functions_total: int = 0
    code_coverage: Optional[float] = Field(None, ge=0.0, le=100.0)
    
    # Quality metrics
    false_positive_rate: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_avg: Optional[float] = Field(None, ge=0.0, le=1.0)
    

class AnalysisReport(BaseModel):
    """Complete analysis report."""
    
    # Identification
    id: UUID = Field(default_factory=uuid4)
    contract_address: Optional[str] = None
    contract_name: str
    
    # Status
    status: AnalysisStatus = AnalysisStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    
    # Configuration used
    analysis_config: Dict[str, Any] = Field(default_factory=dict)
    tools_used: List[str] = Field(default_factory=list)
    
    # Results
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    validated_exploits: List[ValidatedExploit] = Field(default_factory=list)
    tool_results: List[ToolResult] = Field(default_factory=list)
    
    # Metrics
    metrics: AnalysisMetrics = Field(default_factory=AnalysisMetrics)
    
    # Contract info
    contracts_analyzed: List[Contract] = Field(default_factory=list)
    is_multi_contract: bool = False
    
    # Additional info
    notes: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Calculate total analysis duration."""
        if self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def has_critical_findings(self) -> bool:
        """Check if any critical vulnerabilities found."""
        return any(v.severity == SeverityLevel.CRITICAL for v in self.vulnerabilities)
    
    @property
    def has_validated_exploits(self) -> bool:
        """Check if any exploits were validated."""
        return any(e.execution_success for e in self.validated_exploits)
    
    def get_vulnerabilities_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_swc_coverage(self) -> Dict[str, bool]:
        """Get SWC IDs covered in this analysis."""
        covered = {}
        for vuln in self.vulnerabilities:
            if vuln.swc_id:
                covered[vuln.swc_id] = True
        return covered
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10)."""
        if not self.vulnerabilities:
            return 0.0
        
        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 0.5,
        }
        
        total_score = sum(
            severity_weights.get(v.severity, 0) * v.confidence
            for v in self.vulnerabilities
        )
        
        # Normalize to 0-10 scale
        max_possible = len(self.vulnerabilities) * 10.0
        return min(10.0, (total_score / max_possible) * 10) if max_possible > 0 else 0.0
    
    def to_summary(self) -> str:
        """Generate human-readable summary."""
        summary_parts = [
            f"Analysis Report for {self.contract_name}",
            f"Status: {self.status.value}",
            f"Duration: {self.duration or 'In progress'}",
            f"",
            f"Findings Summary:",
            f"- Total Vulnerabilities: {self.metrics.total_vulnerabilities}",
        ]
        
        for severity in SeverityLevel:
            count = self.metrics.by_severity.get(severity, 0)
            if count > 0:
                summary_parts.append(f"  - {severity.value.upper()}: {count}")
        
        if self.validated_exploits:
            summary_parts.extend([
                f"",
                f"Validated Exploits: {len(self.validated_exploits)}",
            ])
        
        summary_parts.extend([
            f"",
            f"Risk Score: {self.calculate_risk_score():.1f}/10",
        ])
        
        return "\n".join(summary_parts)