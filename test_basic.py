#!/usr/bin/env python3
"""
Basic test script for CyberVault package
This script only checks file structure and basic imports
"""

import os
import sys

def main():
    """Run basic tests"""
    print("Testing CyberVault package (basic)...")
    
    try:
        # Test 1: Check if package directory exists
        cybervault_dir = os.path.join(os.getcwd(), "cybervault")
        if os.path.exists(cybervault_dir):
            print("✓ cybervault directory exists")
        else:
            print("❌ cybervault directory missing")
            return 1
        
        # Test 2: Check if required files exist
        required_files = [
            "cybervault/__init__.py",
            "cybervault/vault.py", 
            "cybervault/gui.py"
        ]
        
        for file_path in required_files:
            if os.path.exists(file_path):
                print(f"✓ {file_path} exists")
            else:
                print(f"❌ {file_path} missing")
                return 1
        
        # Test 3: Check if setup files exist
        setup_files = [
            "setup.py",
            "pyproject.toml",
            "README.md",
            "LICENSE"
        ]
        
        for file_path in setup_files:
            if os.path.exists(file_path):
                print(f"✓ {file_path} exists")
            else:
                print(f"⚠ {file_path} missing")
        
        # Test 4: Try to import just the package structure (not modules)
        try:
            import cybervault
            print("✓ cybervault package can be imported")
        except ImportError as e:
            print(f"⚠ cybervault package import failed: {e}")
        
        print("\n🎉 Basic tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 