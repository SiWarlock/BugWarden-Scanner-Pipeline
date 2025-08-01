#!/usr/bin/env python3
"""
Solidity version detection and auto-selection utility.
Parses pragma statements and selects the best available compiler version.
"""

import re
import sys
import subprocess
from pathlib import Path
from typing import Optional, List


def get_available_versions() -> List[str]:
    """Get list of installed solc versions."""
    try:
        result = subprocess.run(
            ["solc-select", "versions"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        # Parse output like "0.8.19 (current)"
        versions = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                version = line.split()[0]
                if version != "Version":  # Skip header
                    versions.append(version)
        return versions
    except subprocess.CalledProcessError:
        return ["0.8.19"]  # Fallback


def parse_pragma_version(content: str) -> Optional[str]:
    """Extract version requirement from pragma solidity statement."""
    # Match patterns like:
    # pragma solidity ^0.8.0;
    # pragma solidity >=0.6.0 <0.8.0;
    # pragma solidity 0.7.6;
    
    pragma_pattern = r'pragma\s+solidity\s+([^;]+);'
    match = re.search(pragma_pattern, content, re.IGNORECASE)
    
    if not match:
        return None
    
    return match.group(1).strip()


def select_best_version(version_spec: str, available: List[str]) -> str:
    """Select the best available version for the given specification."""
    version_spec = version_spec.strip()
    
    # Simple version parsing - handle common cases
    if version_spec.startswith('^'):
        # ^0.8.0 means >=0.8.0 <0.9.0
        base_version = version_spec[1:]
        major, minor = base_version.split('.')[:2]
        
        # Find highest compatible version
        compatible = []
        for v in available:
            v_parts = v.split('.')
            if len(v_parts) >= 2:
                if v_parts[0] == major and v_parts[1] == minor:
                    compatible.append(v)
        
        return max(compatible) if compatible else available[-1]
    
    elif version_spec.startswith('>=') and '<' in version_spec:
        # >=0.6.0 <0.8.0
        # Simple implementation - find something in range
        if '0.6' in version_spec:
            return next((v for v in available if v.startswith('0.6')), available[-1])
        elif '0.7' in version_spec:
            return next((v for v in available if v.startswith('0.7')), available[-1])
    
    elif re.match(r'^\d+\.\d+\.\d+$', version_spec):
        # Exact version like 0.8.19
        return version_spec if version_spec in available else available[-1]
    
    # Default fallback
    return available[-1] if available else "0.8.19"


def detect_and_set_version(contract_path: str) -> str:
    """Detect required Solidity version and set it as current."""
    try:
        # Read contract file
        content = Path(contract_path).read_text()
        
        # Parse pragma
        version_spec = parse_pragma_version(content)
        if not version_spec:
            print(f"No pragma found in {contract_path}, using default 0.8.19")
            return "0.8.19"
        
        # Get available versions
        available = get_available_versions()
        
        # Select best version
        selected = select_best_version(version_spec, available)
        
        # Set the version
        subprocess.run(
            ["solc-select", "use", selected], 
            check=True, 
            capture_output=True
        )
        
        print(f"Selected Solidity {selected} for pragma '{version_spec}'")
        return selected
        
    except Exception as e:
        print(f"Error detecting version: {e}, using default 0.8.19")
        subprocess.run(["solc-select", "use", "0.8.19"], check=True, capture_output=True)
        return "0.8.19"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: detect-solc-version.py <contract_file>")
        sys.exit(1)
    
    contract_file = sys.argv[1]
    version = detect_and_set_version(contract_file)
    print(version)  # Output for scripts to capture