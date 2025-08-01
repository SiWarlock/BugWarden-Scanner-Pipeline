#!/usr/bin/env python3
"""
Slither wrapper script for Docker container execution.
Handles version detection and runs Slither with appropriate settings.
"""

import sys
import os
import json
import subprocess
from pathlib import Path


def run_slither(contract_path: str, output_format: str = "json") -> dict:
    """Run Slither analysis on the given contract."""
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
        
        # Prepare Slither command
        cmd = [
            "slither",
            contract_path,
            "--json", "-"  # Output JSON to stdout
        ]
        
        # Run Slither
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(contract_path) if os.path.isfile(contract_path) else contract_path
        )
        
        # Slither returns non-zero when vulnerabilities are found, which is expected
        # Only treat it as error if there's no JSON output or stderr indicates real failure
        # Slither commonly returns 1 when finding vulnerabilities, which is success
        is_success = result.stdout.strip() and (result.returncode in [0, 1, 255])
        
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
        print("Usage: slither-wrapper.py <contract_path> [output_format]")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "json"
    
    # Verify contract exists
    if not os.path.exists(contract_path):
        print(f"Error: Contract path {contract_path} does not exist")
        sys.exit(1)
    
    # Run analysis
    result = run_slither(contract_path, output_format)
    
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
    
    # Exit with Slither's return code
    sys.exit(result['returncode'])


if __name__ == "__main__":
    main()