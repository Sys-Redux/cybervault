#!/usr/bin/env python3
"""
Structure test script for CyberVault package
This script only checks file structure and package metadata
"""

import os
import sys

def main():
    """Run structure tests"""
    print("Testing CyberVault package structure...")
    
    try:
        # Test 1: Check if we're in the right directory
        print(f"Current directory: {os.getcwd()}")
        
        # Test 2: Check if cybervault directory exists
        cybervault_dir = "cybervault"
        if not os.path.exists(cybervault_dir):
            print(f"❌ {cybervault_dir} directory missing")
            return 1
        print(f"✓ {cybervault_dir} directory exists")
        
        # Test 3: Check required package files
        required_files = [
            "cybervault/__init__.py",
            "cybervault/vault.py",
            "cybervault/gui.py"
        ]
        
        for file_path in required_files:
            if not os.path.exists(file_path):
                print(f"❌ {file_path} missing")
                return 1
            size = os.path.getsize(file_path)
            print(f"✓ {file_path} ({size} bytes)")
        
        # Test 4: Check setup files
        setup_files = [
            "setup.py",
            "pyproject.toml",
            "README.md",
            "LICENSE"
        ]
        
        for file_path in setup_files:
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                print(f"✓ {file_path} ({size} bytes)")
            else:
                print(f"⚠ {file_path} missing")
        
        # Test 5: Check __init__.py content (without importing)
        init_file = "cybervault/__init__.py"
        if os.path.exists(init_file):
            with open(init_file, 'r') as f:
                content = f.read()
                if '__version__' in content:
                    print("✓ __init__.py contains version")
                else:
                    print("⚠ __init__.py missing version")
        
        print("\n🎉 Structure tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Structure test failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 