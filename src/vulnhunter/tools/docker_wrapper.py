"""Docker-based tool wrapper implementation."""

import asyncio
import json
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import shutil
import time

from vulnhunter.tools.base import ToolWrapper, ToolResult, ToolStatus, Finding
from vulnhunter.config.settings import Settings


class DockerToolWrapper(ToolWrapper):
    """Base class for Docker-based analysis tools."""
    
    def __init__(
        self,
        tool_name: str,
        docker_image: str,
        config: Optional[Dict[str, Any]] = None,
        settings: Optional[Settings] = None,
    ):
        """Initialize Docker tool wrapper.
        
        Args:
            tool_name: Name of the tool
            docker_image: Docker image to use
            config: Tool-specific configuration
            settings: Global settings
        """
        super().__init__(tool_name, config)
        self.docker_image = docker_image
        self.settings = settings or Settings()
        # Use timestamp with microseconds and random suffix for uniqueness
        import random
        unique_id = f"{int(time.time() * 1000000)}-{random.randint(1000, 9999)}"
        self.container_name = f"vulnhunter-{tool_name}-{unique_id}"
        self._container_id: Optional[str] = None
    
    async def initialize(self) -> None:
        """Pull Docker image if needed."""
        if self._initialized:
            return
            
        # Check if image exists locally
        cmd = ["docker", "images", "-q", self.docker_image]
        result = await self._run_command(cmd)
        
        if not result[0].strip():
            # Image doesn't exist, pull it
            print(f"Pulling Docker image: {self.docker_image}")
            pull_cmd = ["docker", "pull", self.docker_image]
            stdout, stderr, returncode = await self._run_command(pull_cmd, capture_output=False)
            
            if returncode != 0:
                raise RuntimeError(f"Failed to pull Docker image {self.docker_image}: {stderr}")
        
        self._initialized = True
    
    def is_available(self) -> bool:
        """Check if Docker is available and image exists."""
        try:
            # Check if Docker daemon is running using subprocess directly
            import subprocess
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def analyze(self, contract_path: Path) -> ToolResult:
        """Analyze contract using Docker container.
        
        This method should be overridden by specific tool implementations.
        """
        raise NotImplementedError("Subclasses must implement analyze()")
    
    async def cleanup(self) -> None:
        """Stop and remove container if running."""
        if self._container_id:
            try:
                # Stop container
                await self._run_command(["docker", "stop", self._container_id])
                # Remove container
                await self._run_command(["docker", "rm", self._container_id])
            except Exception as e:
                print(f"Warning: Failed to cleanup container {self._container_id}: {e}")
            finally:
                self._container_id = None
    
    async def run_in_container(
        self,
        command: List[str],
        contract_path: Path,
        working_dir: str = "/contracts",
        additional_volumes: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None,
        network_enabled: bool = False,
    ) -> Tuple[str, str, int]:
        """Run a command in a Docker container.
        
        Args:
            command: Command to run in container
            contract_path: Path to contract file/directory to mount
            working_dir: Working directory inside container
            additional_volumes: Additional volume mounts
            environment: Environment variables
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        # Prepare volume mounts
        volumes = {
            str(contract_path.absolute()): "/contracts",
        }
        if additional_volumes:
            volumes.update(additional_volumes)
        
        # Build docker run command
        docker_cmd = [
            "docker", "run",
            "--rm",  # Remove container after execution
            "--name", self.container_name,
            "-w", working_dir,
        ]
        
        # Add volume mounts
        for host_path, container_path in volumes.items():
            docker_cmd.extend(["-v", f"{host_path}:{container_path}:ro"])
        
        # Add environment variables
        if environment:
            for key, value in environment.items():
                docker_cmd.extend(["-e", f"{key}={value}"])
        
        # Add resource limits
        docker_cmd.extend([
            "--memory", f"{self.config.get('max_memory_mb', 4096)}m",
            "--cpus", str(self.config.get('max_cpus', 2)),
        ])
        
        # Add security options
        docker_cmd.extend([
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
        ])
        
        # Network access control
        if not network_enabled:
            docker_cmd.extend(["--network", "none"])
        
        # Add image and command
        docker_cmd.append(self.docker_image)
        docker_cmd.extend(command)
        
        # Run command with timeout
        timeout = self.config.get('timeout', 300)
        try:
            stdout, stderr, returncode = await self._run_command(docker_cmd, timeout=timeout)
            return stdout, stderr, returncode
        except asyncio.TimeoutError:
            # Kill container on timeout
            await self._run_command(["docker", "kill", self.container_name])
            raise TimeoutError(f"Tool {self.tool_name} timed out after {timeout}s")
    
    async def _run_command(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        capture_output: bool = True,
    ) -> Tuple[str, str, int]:
        """Run a command and return output.
        
        Args:
            cmd: Command to run
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        if capture_output:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(*cmd)
        
        try:
            if timeout:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
            else:
                stdout, stderr = await process.communicate()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
        
        stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
        stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""
        
        return stdout_str, stderr_str, process.returncode
    
    def create_temp_directory(self) -> Path:
        """Create a temporary directory for analysis.
        
        Returns:
            Path to temporary directory
        """
        temp_dir = Path(tempfile.mkdtemp(prefix=f"vulnhunter_{self.tool_name}_"))
        return temp_dir
    
    def copy_contract_files(self, source: Path, dest: Path) -> None:
        """Copy contract files to temporary directory.
        
        Args:
            source: Source file or directory
            dest: Destination directory
        """
        if source.is_file():
            shutil.copy2(source, dest / source.name)
        else:
            # Copy all Solidity files
            for sol_file in source.rglob("*.sol"):
                relative_path = sol_file.relative_to(source)
                dest_file = dest / relative_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(sol_file, dest_file)