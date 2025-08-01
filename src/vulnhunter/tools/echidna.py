"""Echidna property-based fuzzing tool wrapper."""

import json
import re
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import time

from vulnhunter.tools.docker_wrapper import DockerToolWrapper
from vulnhunter.tools.base import ToolResult, ToolStatus, Finding
from vulnhunter.models.vulnerability import VulnerabilityType, VulnerabilityLocation, SeverityLevel


class EchidnaWrapper(DockerToolWrapper):
    """Wrapper for Echidna property-based fuzzing tool."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, settings=None):
        """Initialize Echidna wrapper."""
        super().__init__(
            tool_name="echidna",
            docker_image="vulnhunter-echidna:latest",
            config=config,
            settings=settings,
        )
        
        # Map Echidna findings to vulnerability types
        self.property_to_vuln_type = {
            "balance": VulnerabilityType.UNPROTECTED_ETHER,
            "theft": VulnerabilityType.UNPROTECTED_ETHER,
            "reentrancy": VulnerabilityType.REENTRANCY,
            "overflow": VulnerabilityType.INTEGER_OVERFLOW,
            "underflow": VulnerabilityType.INTEGER_UNDERFLOW,
            "access": VulnerabilityType.ACCESS_CONTROL,
            "dos": VulnerabilityType.DOS_GAS_LIMIT,
        }
    
    async def analyze(self, contract_path: Union[str, Path]) -> ToolResult:
        """Analyze contract with Echidna.
        
        Args:
            contract_path: Path to test contract file (must contain echidna_ properties)
            
        Returns:
            ToolResult with findings
        """
        start_time = time.time()
        
        try:
            # Ensure we have a Path object
            if isinstance(contract_path, str):
                contract_path = Path(contract_path)
            
            # For directory, find test contract
            if contract_path.is_dir():
                # Look for test contracts in echidna subdirectory
                echidna_dir = contract_path / "echidna"
                if echidna_dir.exists():
                    test_files = list(echidna_dir.glob("Test*.sol"))
                else:
                    # Look for any Test*.sol files
                    test_files = list(contract_path.glob("**/Test*.sol"))
                
                if not test_files:
                    return ToolResult(
                        tool_name=self.tool_name,
                        status=ToolStatus.ERROR,
                        findings=[],
                        execution_time=time.time() - start_time,
                        error_message="No Echidna test contracts found (Test*.sol with echidna_ properties)",
                    )
                contract_file = test_files[0].name
                working_dir = test_files[0].parent
            else:
                contract_file = contract_path.name
                working_dir = contract_path.parent
            
            # Use our custom wrapper that handles solc version detection
            command = [
                "python", "/usr/local/bin/echidna-wrapper.py",
                contract_file
            ]
            
            # Run Echidna in container
            stdout, stderr, returncode = await self.run_in_container(
                command=command,
                contract_path=working_dir,
                network_enabled=False,  # No network needed with custom image
            )
            
            # Parse results from wrapper
            findings = self._parse_wrapper_output(stdout, stderr, contract_path)
            
            execution_time = time.time() - start_time
            
            # Echidna returns 1 if properties are violated (which is what we want to find)
            if findings is not None:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.SUCCESS,
                    findings=findings,
                    execution_time=execution_time,
                    raw_output=stdout + "\n" + stderr,
                )
            else:
                return ToolResult(
                    tool_name=self.tool_name,
                    status=ToolStatus.ERROR,
                    findings=[],
                    execution_time=execution_time,
                    error_message=f"Echidna analysis failed. Stderr: {stderr[:500]}",
                    raw_output=stdout + "\n" + stderr,
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
                error_message=f"Echidna analysis failed: {str(e)}",
            )
    
    def _extract_contract_name(self, filename: str) -> str:
        """Extract contract name from filename.
        
        Args:
            filename: Solidity file name
            
        Returns:
            Contract name (assumes Test<ContractName>.sol pattern)
        """
        # Remove .sol extension and Test prefix if present
        name = Path(filename).stem
        if name.startswith("Test"):
            return name
        return f"Test{name}"
    
    def _parse_wrapper_output(self, output: str, stderr: str, contract_path: Path) -> Optional[List[Finding]]:
        """Parse output from echidna-wrapper.py."""
        try:
            # Parse the wrapper JSON output
            wrapper_result = json.loads(output)
            
            if wrapper_result.get("status") != "success":
                return []
            
            # Extract the actual Echidna output
            echidna_stdout = wrapper_result.get("stdout", "")
            echidna_stderr = wrapper_result.get("stderr", "")
            
            # Parse the Echidna output
            return self._parse_output(echidna_stdout, echidna_stderr, contract_path)
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Echidna wrapper parsing error: {e}")
            return []
    
    def _parse_output(self, stdout: str, stderr: str, base_path: Path) -> Optional[List[Finding]]:
        """Parse Echidna output into findings.
        
        Args:
            stdout: Standard output from Echidna
            stderr: Standard error from Echidna
            base_path: Base path for resolving file locations
            
        Returns:
            List of findings or None if parsing failed
        """
        findings = []
        
        try:
            # Try to parse JSON output first
            if stdout.strip() and stdout.strip().startswith("{"):
                try:
                    data = json.loads(stdout)
                    return self._parse_json_output(data, base_path)
                except json.JSONDecodeError:
                    pass
            
            # Fall back to parsing text output
            # Look for failing properties in both stdout and stderr
            full_output = stdout + "\n" + stderr
            
            # Pattern: "echidna_<property>: failed!"
            failed_pattern = re.compile(r"echidna_(\w+):\s*failed", re.IGNORECASE)
            
            for match in failed_pattern.finditer(full_output):
                property_name = match.group(1)
                
                # Try to determine vulnerability type from property name
                vuln_type = VulnerabilityType.UNKNOWN
                for keyword, vtype in self.property_to_vuln_type.items():
                    if keyword in property_name.lower():
                        vuln_type = vtype
                        break
                
                finding = Finding(
                    tool=self.tool_name,
                    title=f"Property Violation: echidna_{property_name}",
                    description=f"Echidna found inputs that violate the property 'echidna_{property_name}'. This indicates a potential vulnerability where the expected invariant can be broken.",
                    vulnerability_type=vuln_type,
                    severity=SeverityLevel.HIGH,  # Property violations are typically serious
                    confidence=0.9,  # High confidence in fuzzing results
                    location=None,  # Echidna doesn't provide line numbers
                    raw_output={"property": property_name, "status": "failed"},
                )
                
                findings.append(finding)
            
            # Also look for assertion failures
            assertion_pattern = re.compile(r"Assertion failed.*?at\s+([^:]+):(\d+)", re.IGNORECASE)
            
            for match in assertion_pattern.finditer(full_output):
                file_path = match.group(1)
                line_num = int(match.group(2))
                
                location = VulnerabilityLocation(
                    file_path=file_path,
                    start_line=line_num,
                    end_line=line_num,
                    code_snippet="",
                )
                
                finding = Finding(
                    tool=self.tool_name,
                    title="Assertion Failure",
                    description="Echidna triggered an assertion failure, indicating a contract invariant was violated.",
                    vulnerability_type=VulnerabilityType.LOGIC_ERROR,
                    severity=SeverityLevel.HIGH,
                    confidence=0.9,
                    location=location,
                    raw_output={"type": "assertion_failure", "line": line_num},
                )
                
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            print(f"Error parsing Echidna output: {e}")
            return None
    
    def _parse_json_output(self, data: dict, base_path: Path) -> List[Finding]:
        """Parse Echidna JSON output format.
        
        Args:
            data: Parsed JSON data
            base_path: Base path for file resolution
            
        Returns:
            List of findings
        """
        findings = []
        
        # Handle different JSON formats Echidna might output
        if "tests" in data:
            for test_name, test_result in data["tests"].items():
                if test_result.get("status") == "failed" or test_result.get("passed") == False:
                    # Extract property name
                    property_name = test_name.replace("echidna_", "")
                    
                    # Determine vulnerability type
                    vuln_type = VulnerabilityType.UNKNOWN
                    for keyword, vtype in self.property_to_vuln_type.items():
                        if keyword in property_name.lower():
                            vuln_type = vtype
                            break
                    
                    finding = Finding(
                        tool=self.tool_name,
                        title=f"Property Violation: {test_name}",
                        description=f"Echidna found inputs that violate the property '{test_name}'. "
                                   f"Counterexample: {test_result.get('counterexample', 'Not provided')}",
                        vulnerability_type=vuln_type,
                        severity=SeverityLevel.HIGH,
                        confidence=0.9,
                        location=None,
                        raw_output=test_result,
                    )
                    
                    findings.append(finding)
        
        return findings