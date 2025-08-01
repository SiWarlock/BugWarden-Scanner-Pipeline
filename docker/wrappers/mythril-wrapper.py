#!/usr/bin/env python3
"""
Mythril wrapper script for Docker container execution.
Handles version detection and runs Mythril with appropriate settings.
"""

import sys
import os
import json
import subprocess
from pathlib import Path


def run_mythril(contract_path: str, output_format: str = "json") -> dict:
    """Run Mythril analysis on the given contract."""
    try:
        # Detect and set appropriate Solidity version
        print(f"Analyzing contract: {contract_path}")
        
        # Auto-detect Solidity version
        version_result = subprocess.run(
            ["detect-solc-version.py", contract_path],
            capture_output=True,
            text=True,
            check=True
        )
        solc_version = version_result.stdout.strip()
        print(f"Using Solidity compiler: {solc_version}")
        
        # Prepare Mythril command with optimized settings
        cmd = [
            "myth", "analyze",
            contract_path,
            "--execution-timeout", "120",  # 2 minute timeout
            "--solver-timeout", "2000",    # 2 seconds per query
            "--max-depth", "8",            # Reasonable analysis depth
            "-o", "json"                   # JSON output
        ]
        
        # Run Mythril
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(contract_path) if os.path.isfile(contract_path) else contract_path
        )
        
        # Mythril returns non-zero when vulnerabilities are found, which is expected
        # Only treat as error if there's no output or stderr indicates real failure
        is_success = result.stdout.strip() and (result.returncode == 0 or result.returncode == 1)
        
        return {
            "status": "success" if is_success else "error",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "solc_version": solc_version
        }
        
    except Exception as e:
        return {
            "status": "error",
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "solc_version": "unknown"
        }


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: mythril-wrapper.py <contract_path> [output_format]")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "json"
    
    # Verify contract exists
    if not os.path.exists(contract_path):
        print(f"Error: Contract path {contract_path} does not exist")
        sys.exit(1)
    
    # Run analysis
    result = run_mythril(contract_path, output_format)
    
    # Output results
    if output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Status: {result['status']}")
        print(f"Solc Version: {result['solc_version']}")
        print(f"Return Code: {result['returncode']}")
        print("\nStdout:")
        print(result['stdout'])
        if result['stderr']:
            print("\nStderr:")
            print(result['stderr'])
    
    # Exit with Mythril's return code
    sys.exit(result['returncode'])


if __name__ == "__main__":
    main()