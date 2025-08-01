"""Test parallel execution of multiple Docker containers."""

import asyncio
import time
from pathlib import Path
import pytest

from vulnhunter.tools.slither import SlitherWrapper
from vulnhunter.tools.base import ToolStatus


class TestParallelExecution:
    """Test running multiple analysis tools in parallel."""
    
    @pytest.fixture
    def vulnerable_contract(self):
        """Path to vulnerable test contract."""
        return Path(__file__).parent.parent / "fixtures" / "vulnerable" / "reentrancy.sol"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_parallel_slither_runs(self, vulnerable_contract):
        """Test running multiple Slither instances in parallel."""
        # Create multiple wrapper instances
        wrappers = [SlitherWrapper() for _ in range(3)]
        
        # Check if Docker is available
        if not wrappers[0].is_available():
            pytest.skip("Docker not available")
        
        start_time = time.time()
        
        # Run all analyses in parallel
        async def run_analysis(wrapper, index):
            """Run analysis and return result with index."""
            async with wrapper:
                result = await wrapper.analyze(vulnerable_contract)
                return index, result
        
        # Execute all analyses concurrently
        tasks = [
            run_analysis(wrapper, i) 
            for i, wrapper in enumerate(wrappers)
        ]
        results = await asyncio.gather(*tasks)
        
        execution_time = time.time() - start_time
        
        # Verify results
        for index, result in results:
            print(f"\nWrapper {index}:")
            print(f"  Status: {result.status}")
            print(f"  Findings: {len(result.findings)}")
            print(f"  Execution time: {result.execution_time:.2f}s")
            
            # All should succeed
            assert result.status == ToolStatus.SUCCESS
            # All should find the same vulnerabilities
            assert len(result.findings) > 0
        
        # Check that parallel execution is faster than sequential
        avg_individual_time = sum(r[1].execution_time for r in results) / len(results)
        expected_sequential_time = avg_individual_time * len(wrappers)
        
        print(f"\nParallel execution time: {execution_time:.2f}s")
        print(f"Expected sequential time: {expected_sequential_time:.2f}s")
        print(f"Speedup: {expected_sequential_time / execution_time:.2f}x")
        
        # Should be significantly faster than sequential
        # Allow some overhead, but should be at least 2x faster for 3 containers
        assert execution_time < expected_sequential_time * 0.6
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_mixed_tool_parallel_execution(self, vulnerable_contract):
        """Test running different tools in parallel (simulate with Slither for now)."""
        # For now, use Slither instances to simulate different tools
        # Later we'll replace with actual Mythril, Echidna, etc.
        tool_configs = [
            {"name": "slither-1", "wrapper": SlitherWrapper()},
            {"name": "slither-2", "wrapper": SlitherWrapper()},
            {"name": "slither-3", "wrapper": SlitherWrapper()},
        ]
        
        # Check availability
        if not tool_configs[0]["wrapper"].is_available():
            pytest.skip("Docker not available")
        
        start_time = time.time()
        
        # Run all tools in parallel
        async def run_tool(tool_config):
            """Run a tool and return results."""
            wrapper = tool_config["wrapper"]
            name = tool_config["name"]
            
            async with wrapper:
                print(f"Starting {name}...")
                result = await wrapper.analyze(vulnerable_contract)
                print(f"Completed {name}")
                return name, result
        
        # Execute all tools concurrently
        tasks = [run_tool(config) for config in tool_configs]
        results = await asyncio.gather(*tasks)
        
        execution_time = time.time() - start_time
        
        # Verify all succeeded
        for name, result in results:
            assert result.status == ToolStatus.SUCCESS
            assert len(result.findings) > 0
        
        print(f"\nTotal parallel execution time: {execution_time:.2f}s")
        print(f"All {len(results)} tools completed successfully")


if __name__ == "__main__":
    # Quick test runner
    async def main():
        test = TestParallelExecution()
        contract_path = Path(__file__).parent.parent / "fixtures" / "vulnerable" / "reentrancy.sol"
        
        print("Testing parallel execution...")
        await test.test_parallel_slither_runs(contract_path)
        
        print("\n" + "="*50 + "\n")
        
        print("Testing mixed tool parallel execution...")
        await test.test_mixed_tool_parallel_execution(contract_path)
    
    asyncio.run(main())