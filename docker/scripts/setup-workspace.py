#!/usr/bin/env python3
"""
Workspace setup utility for analysis tools.
Prepares the environment and detects contract requirements.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any


def find_solidity_files(directory: str) -> List[str]:
    """Find all Solidity files in directory."""
    sol_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sol'):
                sol_files.append(os.path.join(root, file))
    return sol_files


def analyze_contracts(files: List[str]) -> Dict[str, Any]:
    """Analyze contracts and extract metadata."""
    analysis = {
        "total_files": len(files),
        "contracts": [],
        "imports": [],
        "pragma_versions": []
    }
    
    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract contract names
            import re
            contracts = re.findall(r'contract\s+(\w+)', content, re.IGNORECASE)
            
            # Extract imports
            imports = re.findall(r'import\s+"([^"]+)"', content)
            
            # Extract pragma
            pragma = re.search(r'pragma\s+solidity\s+([^;]+);', content, re.IGNORECASE)
            
            analysis["contracts"].extend(contracts)
            analysis["imports"].extend(imports)
            if pragma:
                analysis["pragma_versions"].append(pragma.group(1))
                
        except Exception as e:
            print(f"Warning: Could not analyze {file_path}: {e}")
    
    return analysis


def setup_workspace(contract_path: str) -> Dict[str, Any]:
    """Setup workspace and return analysis info."""
    print(f"Setting up workspace for: {contract_path}")
    
    # Ensure directories exist
    os.makedirs("/results", exist_ok=True)
    os.makedirs("/tmp/crytic-export", exist_ok=True)
    os.makedirs("/tmp/echidna_corpus", exist_ok=True)
    
    # Find Solidity files
    if os.path.isfile(contract_path):
        sol_files = [contract_path]
    else:
        sol_files = find_solidity_files(contract_path)
    
    if not sol_files:
        raise ValueError(f"No Solidity files found in {contract_path}")
    
    # Analyze contracts
    analysis = analyze_contracts(sol_files)
    
    # Set working directory
    if os.path.isfile(contract_path):
        os.chdir(os.path.dirname(contract_path))
    else:
        os.chdir(contract_path)
    
    print(f"Found {analysis['total_files']} Solidity files")
    print(f"Contracts: {', '.join(set(analysis['contracts']))}")
    
    return analysis


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: setup-workspace.py <contracts_path>")
        sys.exit(1)
    
    try:
        result = setup_workspace(sys.argv[1])
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)