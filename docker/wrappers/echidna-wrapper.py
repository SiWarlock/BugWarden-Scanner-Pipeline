#!/usr/bin/env python3
"""
Echidna wrapper script for Docker container execution.
Handles version detection and runs Echidna with appropriate settings.
"""

import sys
import os
import json
import subprocess
from pathlib import Path


def find_echidna_contracts(directory: str) -> list:
    """Find Solidity files that might contain Echidna tests."""
    test_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sol'):
                file_path = os.path.join(root, file)
                # Check if file contains echidna test patterns
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'echidna_' in content.lower() or 'function test' in content.lower():
                            test_files.append(file_path)
                except:
                    continue
    return test_files


def run_echidna(contract_path: str, output_format: str = "json") -> dict:
    """Run Echidna analysis on the given contract."""
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
        
        # Determine contract file and working directory
        if os.path.isfile(contract_path):
            contract_file = os.path.basename(contract_path)
            working_dir = os.path.dirname(contract_path)
        else:
            # Find test contracts in directory
            test_files = find_echidna_contracts(contract_path)
            if not test_files:
                raise Exception(f"No Echidna test contracts found in {contract_path}")
            
            contract_file = os.path.basename(test_files[0])
            working_dir = contract_path
            print(f"Found Echidna test contract: {contract_file}")
        
        # Prepare Echidna command with optimized settings
        cmd = [
            "echidna-test", 
            contract_file,
            "--test-limit", "1000",        # Reasonable number of tests
            "--timeout", "60",             # 1 minute timeout
            "--corpus-dir", "/tmp/echidna_corpus",
            "--format", "text"             # Use text format for now
        ]
        
        # Run Echidna
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        
        # Echidna returns non-zero when property violations are found
        # This is expected behavior, not an error
        is_success = result.returncode in [0, 1] and result.stdout.strip()
        
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
        print("Usage: echidna-wrapper.py <contract_path> [output_format]")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "json"
    
    # Verify contract exists
    if not os.path.exists(contract_path):
        print(f"Error: Contract path {contract_path} does not exist")
        sys.exit(1)
    
    # Run analysis
    result = run_echidna(contract_path, output_format)
    
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
    
    # Exit with Echidna's return code
    sys.exit(result['returncode'])


if __name__ == "__main__":
    main()