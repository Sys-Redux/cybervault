#!/usr/bin/env python3
"""
Minimal test script for CyberVault package
This script performs the most basic tests possible
"""

def main():
    """Run minimal tests"""
    print("Testing CyberVault package (minimal)...")
    
    try:
        # Test 1: Check if we can import the package structure
        import cybervault
        print("✓ cybervault package structure imported")
        
        # Test 2: Check if modules exist (without importing them)
        import os
        cybervault_dir = os.path.dirname(cybervault.__file__)
        
        vault_file = os.path.join(cybervault_dir, "vault.py")
        gui_file = os.path.join(cybervault_dir, "gui.py")
        
        if os.path.exists(vault_file):
            print("✓ vault.py file exists")
        else:
            print("❌ vault.py file missing")
            return 1
            
        if os.path.exists(gui_file):
            print("✓ gui.py file exists")
        else:
            print("❌ gui.py file missing")
            return 1
        
        # Test 3: Check if __init__.py has the right content
        if hasattr(cybervault, '__version__'):
            print(f"✓ Package version: {cybervault.__version__}")
        else:
            print("⚠ No version found")
        
        print("\n🎉 Minimal tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 