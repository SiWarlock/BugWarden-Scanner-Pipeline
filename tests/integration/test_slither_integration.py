"""Integration test for Slither wrapper."""

import asyncio
import pytest
from pathlib import Path

from vulnhunter.tools.slither import SlitherWrapper
from vulnhunter.tools.base import ToolStatus
from vulnhunter.models.vulnerability import VulnerabilityType


class TestSlitherIntegration:
    """Test Slither integration with real contract."""
    
    @pytest.fixture
    def vulnerable_contract(self):
        """Path to vulnerable test contract."""
        return Path(__file__).parent.parent / "fixtures" / "vulnerable" / "reentrancy.sol"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_slither_detects_reentrancy(self, vulnerable_contract):
        """Test that Slither detects reentrancy vulnerability."""
        # Skip if Docker is not available
        wrapper = SlitherWrapper()
        if not wrapper.is_available():
            pytest.skip("Docker not available")
        
        async with wrapper:
            result = await wrapper.analyze(vulnerable_contract)
            
            # Check basic results
            assert result.tool_name == "slither"
            assert result.status == ToolStatus.SUCCESS
            assert len(result.findings) > 0
            
            # Check for reentrancy finding
            reentrancy_findings = [
                f for f in result.findings 
                if f.vulnerability_type == VulnerabilityType.REENTRANCY
            ]
            assert len(reentrancy_findings) > 0
            
            # Verify the finding details
            reentrancy = reentrancy_findings[0]
            assert "withdraw" in reentrancy.description.lower()
            assert reentrancy.severity.value in ["high", "medium"]
            assert reentrancy.confidence >= 0.7
            
            # Check SWC mapping
            assert reentrancy.raw_output.get("swc_id") == "SWC-107"
    
    @pytest.mark.asyncio
    @pytest.mark.integration 
    async def test_slither_timeout_handling(self, vulnerable_contract):
        """Test timeout handling."""
        wrapper = SlitherWrapper(config={"timeout": 1})  # 1 second timeout
        
        if not wrapper.is_available():
            pytest.skip("Docker not available")
        
        # This should complete quickly, so let's test with a more complex scenario
        # For now, just verify the wrapper handles timeouts gracefully
        async with wrapper:
            result = await wrapper.analyze(vulnerable_contract)
            # Should complete before timeout
            assert result.status in [ToolStatus.SUCCESS, ToolStatus.TIMEOUT]


if __name__ == "__main__":
    # Quick test runner
    async def main():
        wrapper = SlitherWrapper()
        contract_path = Path(__file__).parent.parent / "fixtures" / "vulnerable"
        
        print("Testing Slither wrapper...")
        print(f"Docker available: {wrapper.is_available()}")
        
        if wrapper.is_available():
            async with wrapper:
                result = await wrapper.analyze(contract_path)
                
                print(f"\nStatus: {result.status}")
                print(f"Execution time: {result.execution_time:.2f}s")
                print(f"Findings: {len(result.findings)}")
                
                if result.error_message:
                    print(f"Error: {result.error_message}")
                elif result.status == ToolStatus.ERROR and result.raw_output:
                    print(f"Raw output: {result.raw_output[:500]}...")
                
                for finding in result.findings:
                    print(f"\n- {finding.title}")
                    print(f"  Type: {finding.vulnerability_type.value}")
                    print(f"  Severity: {finding.severity.value}")
                    print(f"  Confidence: {finding.confidence:.0%}")
                    if finding.location:
                        print(f"  Location: {finding.location.file_path}:{finding.location.start_line}")
    
    asyncio.run(main())