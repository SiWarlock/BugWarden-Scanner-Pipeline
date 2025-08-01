"""Slither static analysis tool wrapper."""

import json
import re
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import time

from vulnhunter.tools.docker_wrapper import DockerToolWrapper
from vulnhunter.tools.base import ToolResult, ToolStatus, Finding
from vulnhunter.models.vulnerability import VulnerabilityType, VulnerabilityLocation, SeverityLevel


class SlitherWrapper(DockerToolWrapper):
    """Wrapper for Slither static analysis tool."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, settings=None):
        """Initialize Slither wrapper."""
        super().__init__(
            tool_name="slither",
            docker_image="vulnhunter-slither:latest",
            config=config,
            settings=settings,
        )
        
        # Map Slither detector IDs to our vulnerability types
        self.detector_mapping = {
            "reentrancy-eth": VulnerabilityType.REENTRANCY,
            "reentrancy-no-eth": VulnerabilityType.REENTRANCY,
            "reentrancy-benign": VulnerabilityType.REENTRANCY,
            "reentrancy-events": VulnerabilityType.REENTRANCY,
            "reentrancy-unlimited-gas": VulnerabilityType.REENTRANCY,
            "unprotected-upgrade": VulnerabilityType.ACCESS_CONTROL,
            "suicidal": VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
            "unchecked-transfer": VulnerabilityType.UNCHECKED_CALL,
            "unchecked-lowlevel": VulnerabilityType.UNCHECKED_CALL,
            "unchecked-send": VulnerabilityType.UNCHECKED_SEND,
            "arbitrary-send": VulnerabilityType.UNPROTECTED_ETHER,
            "controlled-delegatecall": VulnerabilityType.DELEGATECALL,
            "delegatecall-loop": VulnerabilityType.DELEGATECALL,
            "timestamp": VulnerabilityType.TIMESTAMP_DEPENDENCE,
            "weak-prng": VulnerabilityType.WEAK_RANDOMNESS,
            "divide-before-multiply": VulnerabilityType.INTEGER_OVERFLOW,
            "locked-ether": VulnerabilityType.UNEXPECTED_ETHER,
            "tx-origin": VulnerabilityType.ACCESS_CONTROL,
            "shadowing-state": VulnerabilityType.SHADOWING,
            "incorrect-equality": VulnerabilityType.LOGIC_ERROR,
            "uninitialized-state": VulnerabilityType.LOGIC_ERROR,
            "uninitialized-storage": VulnerabilityType.LOGIC_ERROR,
            "uninitialized-local": VulnerabilityType.LOGIC_ERROR,
            "pragma": VulnerabilityType.FLOATING_PRAGMA,
            "solc-version": VulnerabilityType.OUTDATED_COMPILER,
        }
        
        # SWC mapping for common vulnerabilities
        self.swc_mapping = {
            VulnerabilityType.REENTRANCY: "SWC-107",
            VulnerabilityType.INTEGER_OVERFLOW: "SWC-101",
            VulnerabilityType.INTEGER_UNDERFLOW: "SWC-101",
            VulnerabilityType.UNPROTECTED_SELFDESTRUCT: "SWC-106",
            VulnerabilityType.UNPROTECTED_ETHER: "SWC-105",
            VulnerabilityType.UNCHECKED_CALL: "SWC-104",
            VulnerabilityType.FLOATING_PRAGMA: "SWC-103",
            VulnerabilityType.OUTDATED_COMPILER: "SWC-102",
            VulnerabilityType.DELEGATECALL: "SWC-112",
            VulnerabilityType.WEAK_RANDOMNESS: "SWC-120",
            VulnerabilityType.TIMESTAMP_DEPENDENCE: "SWC-116",
            VulnerabilityType.SHADOWING: "SWC-119",
            VulnerabilityType.UNCHECKED_SEND: "SWC-113",
            VulnerabilityType.ACCESS_CONTROL: "SWC-115",
        }
    
    async def analyze(self, contract_path: Union[str, Path]) -> ToolResult:
        """Analyze contract with Slither.
        
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
            
            # Determine the target file/directory
            if contract_path.is_file():
                target = contract_path.name
                working_dir = contract_path.parent
            else:
                target = "."
                working_dir = contract_path
            
            # Use our custom wrapper that handles solc version detection
            command = [
                "python", "/usr/local/bin/slither-wrapper.py",
                target
            ]

            # Run Slither in container (no network needed - solc pre-installed)
            stdout, stderr, returncode = await self.run_in_container(
                command=command,
                contract_path=working_dir,
                network_enabled=False,  # No network needed!
            )
            
            # Parse results from wrapper  
            findings = self._parse_wrapper_output(stdout, stderr, contract_path)
            
            execution_time = time.time() - start_time
            
            # Slither returns non-zero on findings, so check if we got valid JSON
            if findings is not None:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    findings=findings,
                    execution_time=execution_time,
                    raw_output=stdout,
                )
            else:
                # If no findings parsed but Slither ran, it might mean no vulnerabilities
                if stdout and ("success" in stdout or "detectors" in stdout):
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
                        error_message=f"Failed to parse Slither output. Stderr: {stderr[:200]}",
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
                error_message=f"Slither analysis failed: {str(e)}",
            )
    
    def _parse_wrapper_output(self, output: str, stderr: str, contract_path: Path) -> Optional[List[Finding]]:
        """Parse output from slither-wrapper.py."""
        try:
            # Parse the wrapper JSON output
            wrapper_result = json.loads(output)
            
            if wrapper_result.get("status") != "success":
                return []
            
            # Extract the actual Slither output
            slither_output = wrapper_result.get("stdout", "")
            
            # Parse the Slither JSON output
            return self._parse_output(slither_output, contract_path)
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Slither wrapper parsing error: {e}")
            return []
    
    def _parse_output(self, output: str, base_path: Path) -> Optional[List[Finding]]:
        """Parse Slither JSON output into findings.
        
        Args:
            output: Raw JSON output from Slither
            base_path: Base path for resolving file locations
            
        Returns:
            List of findings or None if parsing failed
        """
        try:
            if not output.strip():
                return []
            
            # Extract JSON from output (skip debug messages from wrapper)
            json_start = output.find('{')
            if json_start == -1:
                return []
            
            json_output = output[json_start:]
            
            # Parse JSON output from our wrapper
            wrapper_data = json.loads(json_output)
            
            # Check if wrapper succeeded
            if wrapper_data.get("status") != "success":
                print(f"Slither wrapper failed: {wrapper_data.get('stderr', 'Unknown error')}")
                return []
            

            
            # Parse the actual Slither output
            slither_output = wrapper_data.get("stdout", "")
            if not slither_output.strip():
                return []
            
            data = json.loads(slither_output)
            
            if not data.get("success", False):
                return None
            
            findings = []
            results = data.get("results", {})
            detectors = results.get("detectors", [])
            
            for detector in detectors:
                # Extract basic info
                check = detector.get("check", "unknown")
                impact = detector.get("impact", "Medium")
                confidence = detector.get("confidence", "Medium")
                description = detector.get("description", "")
                
                # Map to our types
                vuln_type = self.detector_mapping.get(check, VulnerabilityType.UNKNOWN)
                swc_id = self.swc_mapping.get(vuln_type)
                
                # Extract location from first element if available
                location = None
                elements = detector.get("elements", [])
                if elements and len(elements) > 0:
                    element = elements[0]
                    source_mapping = element.get("source_mapping", {})
                    if source_mapping:
                        location = VulnerabilityLocation(
                            file_path=source_mapping.get("filename", ""),
                            start_line=source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0,
                            end_line=source_mapping.get("lines", [0])[-1] if source_mapping.get("lines") else 0,
                            code_snippet=element.get("source", ""),
                        )
                
                # Create finding
                finding = Finding(
                    tool=self.tool_name,
                    title=detector.get("check", "Unknown Issue"),
                    description=description,
                    vulnerability_type=vuln_type,
                    severity=self._map_severity(impact),
                    confidence=self._confidence_to_score(confidence),
                    location=location,
                    raw_output=detector,
                )
                
                # Add SWC ID to metadata
                if swc_id:
                    finding.raw_output["swc_id"] = swc_id
                
                findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse Slither JSON: {e}")
            return None
        except Exception as e:
            print(f"Error parsing Slither output: {e}")
            return None
    
    def _map_severity(self, impact: str) -> SeverityLevel:
        """Map Slither impact to our severity levels.
        
        Args:
            impact: Slither impact level
            
        Returns:
            Standardized severity level
        """
        mapping = {
            "High": SeverityLevel.HIGH,
            "Medium": SeverityLevel.MEDIUM,
            "Low": SeverityLevel.LOW,
            "Informational": SeverityLevel.INFO,
            "Optimization": SeverityLevel.INFO,
        }
        return mapping.get(impact, SeverityLevel.MEDIUM)
    
    def _confidence_to_score(self, confidence: str) -> float:
        """Convert Slither confidence to numeric score.
        
        Args:
            confidence: Slither confidence level
            
        Returns:
            Confidence score between 0 and 1
        """
        mapping = {
            "High": 0.9,
            "Medium": 0.7,
            "Low": 0.5,
        }
        return mapping.get(confidence, 0.7)