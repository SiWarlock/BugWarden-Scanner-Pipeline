"""Tests for DockerToolWrapper."""

import asyncio
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from vulnhunter.tools.docker_wrapper import DockerToolWrapper
from vulnhunter.tools.base import ToolResult, ToolStatus


class TestDockerWrapper(DockerToolWrapper):
    """Test implementation of DockerToolWrapper."""
    
    async def analyze(self, contract_path: Path) -> ToolResult:
        """Simple analyze implementation for testing."""
        return ToolResult(
            tool_name=self.tool_name,
            status=ToolStatus.SUCCESS,
            findings=[],
            execution_time=1.0,
        )


class TestDockerToolWrapper:
    """Test DockerToolWrapper functionality."""
    
    @pytest.fixture
    def wrapper(self):
        """Create test wrapper instance."""
        return TestDockerWrapper(
            tool_name="test-tool",
            docker_image="test-image:latest",
        )
    
    @pytest.mark.asyncio
    async def test_initialization(self, wrapper):
        """Test wrapper initialization."""
        assert wrapper.tool_name == "test-tool"
        assert wrapper.docker_image == "test-image:latest"
        assert not wrapper._initialized
        assert wrapper.container_name.startswith("vulnhunter-test-tool-")
    
    @pytest.mark.asyncio
    async def test_is_available(self, wrapper):
        """Test Docker availability check."""
        with patch.object(wrapper, '_run_command') as mock_run:
            mock_run.return_value = ("", "", 0)
            assert wrapper.is_available()
            
            mock_run.return_value = ("", "error", 1)
            assert not wrapper.is_available()
    
    @pytest.mark.asyncio
    async def test_run_command(self, wrapper):
        """Test command execution."""
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"output", b"error")
            mock_process.returncode = 0
            mock_exec.return_value = mock_process
            
            stdout, stderr, code = await wrapper._run_command(["echo", "test"])
            
            assert stdout == "output"
            assert stderr == "error"
            assert code == 0
            mock_exec.assert_called_once_with(
                "echo", "test",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
    
    def test_copy_contract_files(self, wrapper, tmp_path):
        """Test contract file copying."""
        # Create test files
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "contract.sol").write_text("contract Test {}")
        (source_dir / "nested" / "other.sol").mkdir(parents=True)
        (source_dir / "nested" / "other.sol").write_text("contract Other {}")
        
        dest_dir = tmp_path / "dest"
        dest_dir.mkdir()
        
        # Copy files
        wrapper.copy_contract_files(source_dir, dest_dir)
        
        # Verify files copied
        assert (dest_dir / "contract.sol").exists()
        assert (dest_dir / "nested" / "other.sol").exists()
        assert (dest_dir / "contract.sol").read_text() == "contract Test {}"