"""Mythril symbolic execution tool wrapper."""

import json
import re
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import time

from vulnhunter.tools.docker_wrapper import DockerToolWrapper
from vulnhunter.tools.base import ToolResult, ToolStatus, Finding
from vulnhunter.models.vulnerability import VulnerabilityType, VulnerabilityLocation, SeverityLevel


class MythrilWrapper(DockerToolWrapper):
    """Wrapper for Mythril symbolic execution tool."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, settings=None):
        """Initialize Mythril wrapper."""
        super().__init__(
            tool_name="mythril",
            docker_image="vulnhunter-mythril:latest",
            config=config,
            settings=settings,
        )
        
        # Map Mythril SWC IDs to our vulnerability types
        self.swc_to_vuln_type = {
            "SWC-101": VulnerabilityType.INTEGER_OVERFLOW,  # Integer Overflow and Underflow
            "SWC-104": VulnerabilityType.UNCHECKED_CALL,    # Unchecked Call Return Value
            "SWC-105": VulnerabilityType.UNPROTECTED_ETHER, # Unprotected Ether Withdrawal
            "SWC-106": VulnerabilityType.UNPROTECTED_SELFDESTRUCT,  # Unprotected SELFDESTRUCT
            "SWC-107": VulnerabilityType.REENTRANCY,        # Reentrancy
            "SWC-110": VulnerabilityType.LOGIC_ERROR,       # Assert Violation -> Logic Error
            "SWC-112": VulnerabilityType.DELEGATECALL,      # Delegatecall to Untrusted Callee
            "SWC-113": VulnerabilityType.UNCHECKED_SEND,    # DoS with Failed Call
            "SWC-115": VulnerabilityType.ACCESS_CONTROL,    # Authorization through tx.origin
            "SWC-116": VulnerabilityType.TIMESTAMP_DEPENDENCE,  # Block values as a proxy for time
            "SWC-120": VulnerabilityType.WEAK_RANDOMNESS,   # Weak Sources of Randomness
            "SWC-124": VulnerabilityType.ACCESS_CONTROL,    # Write to Arbitrary Storage -> Access Control
            "SWC-128": VulnerabilityType.DOS_GAS_LIMIT,     # DoS With Block Gas Limit
        }
    
    async def analyze(self, contract_path: Union[str, Path]) -> ToolResult:
        """Analyze contract with Mythril.
        
        Args:
            contract_path: Path to contract file or directory
            
        Returns:
            ToolResult with findings
        """
        start_time = time.time()
        
        try:
            # Ensure we have a Path object
            if isinstance(contract_path, str):
                contract_path = Path(contract_path)
            
            # For directory, find the main contract file
            if contract_path.is_dir():
                sol_files = list(contract_path.glob("*.sol"))
                if not sol_files:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.ERROR,
                        findings=[],
                        execution_time=time.time() - start_time,
                        error_message="No Solidity files found in directory",
                    )
                # Use the first .sol file for now
                contract_file = sol_files[0].name
            else:
                contract_file = contract_path.name
            
            # Prepare command - use simpler/faster settings
            # Use our custom wrapper that handles solc version detection
            command = [
                "python", "/usr/local/bin/mythril-wrapper.py",
                contract_file
            ]
            
            # Run Mythril in container
            stdout, stderr, returncode = await self.run_in_container(
                command=command,
                contract_path=contract_path if contract_path.is_dir() else contract_path.parent,
                network_enabled=False,  # Mythril doesn't need network
            )
            
            # Parse results from wrapper
            findings = self._parse_wrapper_output(stdout, stderr, contract_path)
            
            execution_time = time.time() - start_time
            
            # Mythril returns 0 on success (even with findings)
            if findings is not None:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    findings=findings,
                    execution_time=execution_time,
                    raw_output=stdout,
                )
            else:
                # Check if it's just no vulnerabilities found
                if returncode == 0 and "The analysis was completed successfully" in stderr:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.SUCCESS,
                        findings=[],
                        execution_time=execution_time,
                        raw_output=stdout,
                    )
                else:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.ERROR,
                        findings=[],
                        execution_time=execution_time,
                        error_message=f"Mythril analysis failed. Stderr: {stderr[:500]}",
                        raw_output=stdout,
                    )
                
        except TimeoutError as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                findings=[],
                execution_time=time.time() - start_time,
                error_message=str(e),
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                findings=[],
                execution_time=time.time() - start_time,
                error_message=f"Mythril analysis failed: {str(e)}",
            )
    
    def _parse_wrapper_output(self, output: str, stderr: str, contract_path: Path) -> Optional[List[Finding]]:
        """Parse output from mythril-wrapper.py."""
        try:
            # Parse the wrapper JSON output
            wrapper_result = json.loads(output)
            
            if wrapper_result.get("status") != "success":
                return []
            
            # Extract the actual Mythril output
            mythril_output = wrapper_result.get("stdout", "")
            
            # Parse the Mythril JSON output
            return self._parse_output(mythril_output, contract_path)
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Mythril wrapper parsing error: {e}")
            return []
    
    def _parse_output(self, output: str, base_path: Path) -> Optional[List[Finding]]:
        """Parse Mythril JSON output into findings.
        
        Args:
            output: Raw JSON output from Mythril
            base_path: Base path for resolving file locations
            
        Returns:
            List of findings or None if parsing failed
        """
        try:
            # Parse JSON output
            if not output.strip():
                return []
            

            
            data = json.loads(output)
            
            # Check structure - Mythril can output as dict or list
            issues = []
            if isinstance(data, dict):
                # Standard format has 'issues' key
                if 'issues' in data:
                    issues = data['issues']
                elif 'results' in data:
                    issues = data['results']
                else:
                    return []
            elif isinstance(data, list):
                issues = data
            else:
                return None
            
            findings = []
            
            # Process each issue
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                
                # Extract SWC ID and map to vulnerability type
                swc_id = issue.get("swc-id") or issue.get("swcID") or ""
                vuln_type = self.swc_to_vuln_type.get(swc_id, VulnerabilityType.UNKNOWN)
                
                # Extract location information - handle different formats
                location = None
                lineno = issue.get("lineno", 0)
                if lineno:
                    location = VulnerabilityLocation(
                        file_path=issue.get("filename", ""),
                        start_line=lineno,
                        end_line=lineno,
                        code_snippet=issue.get("code", ""),
                    )
                
                # Create finding
                finding = Finding(
                    tool=self.tool_name,
                    title=issue.get("title", "Unknown Issue"),
                    description=issue.get("description", ""),
                    vulnerability_type=vuln_type,
                    severity=self._map_severity(issue.get("severity", "Medium")),
                    confidence=0.8,  # Mythril is generally high confidence
                    location=location,
                    raw_output=issue,
                )
                
                # Add SWC ID to metadata
                finding.raw_output["swc_id"] = swc_id
                
                findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse Mythril JSON: {e}")
            print(f"Output: {output[:500]}")
            return None
        except Exception as e:
            print(f"Error parsing Mythril output: {e}")
            return None
    
    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map Mythril severity to our severity levels.
        
        Args:
            severity: Mythril severity level
            
        Returns:
            Standardized severity level
        """
        mapping = {
            "High": SeverityLevel.HIGH,
            "Medium": SeverityLevel.MEDIUM,
            "Low": SeverityLevel.LOW,
            "Informational": SeverityLevel.INFO,
        }
        return mapping.get(severity, SeverityLevel.MEDIUM)