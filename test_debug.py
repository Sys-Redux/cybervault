#!/usr/bin/env python3
"""
Debug test script for CyberVault package
This script provides detailed information about the environment and failures
"""

import os
import sys
import platform

def main():
    """Run debug tests"""
    print("=== CyberVault Debug Test ===")
    print(f"Platform: {platform.platform()}")
    print(f"Python version: {sys.version}")
    print(f"Current directory: {os.getcwd()}")
    print(f"Python executable: {sys.executable}")
    
    try:
        # Test 1: List directory contents
        print("\n=== Directory Contents ===")
        for item in os.listdir('.'):
            if os.path.isdir(item):
                print(f"📁 {item}/")
            else:
                print(f"📄 {item}")
        
        # Test 2: Check cybervault directory
        print("\n=== CyberVault Directory ===")
        cybervault_dir = "cybervault"
        if os.path.exists(cybervault_dir):
            print(f"✓ {cybervault_dir} exists")
            for item in os.listdir(cybervault_dir):
                print(f"  - {item}")
        else:
            print(f"❌ {cybervault_dir} missing")
            return 1
        
        # Test 3: Check specific files
        print("\n=== File Checks ===")
        files_to_check = [
            "cybervault/__init__.py",
            "cybervault/vault.py",
            "cybervault/gui.py",
            "setup.py",
            "pyproject.toml"
        ]
        
        for file_path in files_to_check:
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                print(f"✓ {file_path} ({size} bytes)")
            else:
                print(f"❌ {file_path} missing")
        
        # Test 4: Try to import package
        print("\n=== Import Tests ===")
        try:
            import cybervault
            print("✓ cybervault package imported")
            print(f"  Package location: {cybervault.__file__}")
        except Exception as e:
            print(f"❌ cybervault import failed: {e}")
            return 1
        
        # Test 5: Try to import modules (with detailed error info)
        print("\n=== Module Import Tests ===")
        
        try:
            from cybervault import vault
            print("✓ vault module imported")
        except Exception as e:
            print(f"❌ vault import failed: {type(e).__name__}: {e}")
        
        try:
            from cybervault import gui
            print("✓ gui module imported")
        except Exception as e:
            print(f"❌ gui import failed: {type(e).__name__}: {e}")
        
        print("\n=== Debug Test Complete ===")
        return 0
        
    except Exception as e:
        print(f"\n❌ Debug test failed: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main()) 