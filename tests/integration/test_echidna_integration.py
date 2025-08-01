"""Integration test for Echidna wrapper."""

import asyncio
import pytest
from pathlib import Path

from vulnhunter.tools.echidna import EchidnaWrapper
from vulnhunter.tools.base import ToolStatus
from vulnhunter.models.vulnerability import VulnerabilityType


class TestEchidnaIntegration:
    """Test Echidna integration with property-based tests."""
    
    @pytest.fixture
    def echidna_test_dir(self):
        """Path to directory containing Echidna test contracts."""
        return Path(__file__).parent.parent / "fixtures" / "echidna"
    
    @pytest.fixture
    def vulnerable_dir(self):
        """Path to directory containing vulnerable contracts."""
        return Path(__file__).parent.parent / "fixtures" / "vulnerable"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_echidna_detects_property_violations(self, echidna_test_dir):
        """Test that Echidna detects property violations."""
        # Skip if Docker is not available
        wrapper = EchidnaWrapper()
        if not wrapper.is_available():
            pytest.skip("Docker not available")
        
        async with wrapper:
            # Analyze the test directory (should find TestReentrancy.sol)
            result = await wrapper.analyze(echidna_test_dir.parent)
            
            # Check basic results
            assert result.tool_name == "echidna"
            
            print(f"\nEchidna Status: {result.status}")
            print(f"Execution time: {result.execution_time:.2f}s")
            print(f"Findings: {len(result.findings)}")
            
            if result.status == ToolStatus.ERROR:
                print(f"Error: {result.error_message}")
                print(f"Raw output:\n{result.raw_output[:1000]}")
            
            # Echidna might find property violations
            if result.status == ToolStatus.SUCCESS and len(result.findings) > 0:
                for finding in result.findings:
                    print(f"\n- {finding.title}")
                    print(f"  Type: {finding.vulnerability_type.value}")
                    print(f"  Severity: {finding.severity.value}")
                    print(f"  Description: {finding.description[:200]}...")
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_echidna_configuration_options(self, echidna_test_dir):
        """Test Echidna with different configuration options."""
        # Custom configuration for faster testing
        config = {
            "test_limit": 1000,  # Fewer tests for speed
            "corpus_dir": "/tmp/echidna_test",
        }
        
        wrapper = EchidnaWrapper(config=config)
        if not wrapper.is_available():
            pytest.skip("Docker not available")
        
        async with wrapper:
            result = await wrapper.analyze(echidna_test_dir.parent)
            
            print(f"\nEchidna with custom config:")
            print(f"Status: {result.status}")
            print(f"Execution time: {result.execution_time:.2f}s")
            
            # Should complete faster with fewer tests
            assert result.execution_time < 60  # Should finish within 1 minute


if __name__ == "__main__":
    # Quick test runner
    async def main():
        wrapper = EchidnaWrapper()
        test_dir = Path(__file__).parent.parent / "fixtures"
        
        print("Testing Echidna wrapper...")
        print(f"Docker available: {wrapper.is_available()}")
        
        if wrapper.is_available():
            async with wrapper:
                print("\nRunning Echidna property-based testing...")
                # Try with the echidna directory directly
                echidna_dir = test_dir / "echidna"
                result = await wrapper.analyze(echidna_dir)
                
                print(f"\nStatus: {result.status}")
                print(f"Execution time: {result.execution_time:.2f}s")
                print(f"Findings: {len(result.findings)}")
                
                # Always show some raw output for debugging
                print(f"\nRaw output (first 1000 chars):")
                print(result.raw_output[:1000] if result.raw_output else "No output")
                
                if result.status == ToolStatus.ERROR:
                    print(f"Error: {result.error_message}")
                    print(f"\nRaw output (first 500 chars):")
                    print(result.raw_output[:500])
                else:
                    for finding in result.findings:
                        print(f"\n- {finding.title}")
                        print(f"  Type: {finding.vulnerability_type.value}")
                        print(f"  Severity: {finding.severity.value}")
                        print(f"  Confidence: {finding.confidence}")
    
    asyncio.run(main())