#!/usr/bin/env python3
"""
Simple test script for CyberVault package
This script performs basic tests that should work on all platforms
"""

def main():
    """Run basic tests"""
    print("Testing CyberVault package...")
    
    try:
        # Test 1: Import the package
        import cybervault
        print("✓ cybervault package imported")
        
        # Test 2: Import modules
        from cybervault import vault
        print("✓ vault module imported")
        
        from cybervault import gui
        print("✓ gui module imported")
        
        # Test 3: Check functions exist
        assert hasattr(vault, 'main'), "vault.main should exist"
        print("✓ vault.main function exists")
        
        assert hasattr(gui, 'main'), "gui.main should exist"
        print("✓ gui.main function exists")
        
        # Test 4: Check VaultGUI class
        from cybervault.gui import VaultGUI
        print("✓ VaultGUI class imported")
        
        print("\n🎉 All basic tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 