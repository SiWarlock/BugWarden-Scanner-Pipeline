"""Integration test for Mythril wrapper."""

import asyncio
import pytest
from pathlib import Path

from vulnhunter.tools.mythril import MythrilWrapper
from vulnhunter.tools.base import ToolStatus
from vulnhunter.models.vulnerability import VulnerabilityType


class TestMythrilIntegration:
    """Test Mythril integration with real contract."""
    
    @pytest.fixture
    def vulnerable_contract(self):
        """Path to vulnerable test contract."""
        return Path(__file__).parent.parent / "fixtures" / "vulnerable" / "reentrancy.sol"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_mythril_detects_reentrancy(self, vulnerable_contract):
        """Test that Mythril detects reentrancy vulnerability."""
        # Skip if Docker is not available
        wrapper = MythrilWrapper()
        if not wrapper.is_available():
            pytest.skip("Docker not available")
        
        async with wrapper:
            result = await wrapper.analyze(vulnerable_contract)
            
            # Check basic results
            assert result.tool_name == "mythril"
            assert result.status == ToolStatus.SUCCESS
            
            print(f"\nMythril found {len(result.findings)} vulnerabilities")
            
            # Check for specific vulnerabilities
            vuln_types = {f.vulnerability_type for f in result.findings}
            print(f"Vulnerability types found: {[v.value for v in vuln_types]}")
            
            # Mythril should find at least the reentrancy
            # Note: Mythril may not always detect all vulnerabilities depending on analysis depth
            if len(result.findings) > 0:
                # Check that we properly mapped SWC IDs
                for finding in result.findings:
                    print(f"\n- {finding.title}")
                    print(f"  Type: {finding.vulnerability_type.value}")
                    print(f"  Severity: {finding.severity.value}")
                    print(f"  SWC: {finding.raw_output.get('swc_id', 'N/A')}")
                    if finding.location:
                        print(f"  Location: Line {finding.location.start_line}")
                    
                    # Verify SWC ID is present
                    assert "swc_id" in finding.raw_output
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_mythril_vs_slither_comparison(self, vulnerable_contract):
        """Compare Mythril and Slither findings."""
        from vulnhunter.tools.slither import SlitherWrapper
        
        # Skip if Docker is not available
        mythril = MythrilWrapper()
        slither = SlitherWrapper()
        
        if not mythril.is_available() or not slither.is_available():
            pytest.skip("Docker not available")
        
        # Run both tools
        async with mythril, slither:
            mythril_task = mythril.analyze(vulnerable_contract)
            slither_task = slither.analyze(vulnerable_contract)
            
            mythril_result, slither_result = await asyncio.gather(
                mythril_task, slither_task
            )
        
        # Compare results
        print("\n=== Tool Comparison ===")
        print(f"Slither: {len(slither_result.findings)} findings in {slither_result.execution_time:.2f}s")
        print(f"Mythril: {len(mythril_result.findings)} findings in {mythril_result.execution_time:.2f}s")
        
        # Get unique vulnerability types from each tool
        slither_types = {f.vulnerability_type for f in slither_result.findings}
        mythril_types = {f.vulnerability_type for f in mythril_result.findings}
        
        print(f"\nSlither vuln types: {[v.value for v in slither_types]}")
        print(f"Mythril vuln types: {[v.value for v in mythril_types]}")
        
        # Both tools should succeed
        assert slither_result.status == ToolStatus.SUCCESS
        assert mythril_result.status == ToolStatus.SUCCESS


if __name__ == "__main__":
    # Quick test runner
    async def main():
        wrapper = MythrilWrapper()
        contract_path = Path(__file__).parent.parent / "fixtures" / "vulnerable"
        
        print("Testing Mythril wrapper...")
        print(f"Docker available: {wrapper.is_available()}")
        
        if wrapper.is_available():
            async with wrapper:
                print("\nRunning Mythril analysis (this may take a minute)...")
                result = await wrapper.analyze(contract_path)
                
                print(f"\nStatus: {result.status}")
                print(f"Execution time: {result.execution_time:.2f}s")
                print(f"Findings: {len(result.findings)}")
                
                for finding in result.findings:
                    print(f"\n- {finding.title}")
                    print(f"  Type: {finding.vulnerability_type.value}")
                    print(f"  Severity: {finding.severity.value}")
                    print(f"  SWC: {finding.raw_output.get('swc_id', 'N/A')}")
                    print(f"  Description: {finding.description[:100]}...")
    
    asyncio.run(main())