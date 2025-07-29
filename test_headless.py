#!/usr/bin/env python3
"""
Headless test script for CyberVault package
This script can run in CI environments without a display
"""

import os
import sys

def test_imports():
    """Test that all modules can be imported"""
    try:
        import cybervault
        print("✓ cybervault package imported successfully")
        
        from cybervault import vault, gui
        print("✓ vault and gui modules imported successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_vault_functions():
    """Test basic vault functionality"""
    try:
        from cybervault import vault
        
        # Test that the main function exists
        assert hasattr(vault, 'main'), "vault module should have main function"
        print("✓ vault module has main function")
        
        # Test that key functions exist
        assert hasattr(vault, 'load_vault'), "vault module should have load_vault function"
        assert hasattr(vault, 'save_vault'), "vault module should have save_vault function"
        print("✓ vault module has required functions")
        
        return True
    except Exception as e:
        print(f"✗ Vault test failed: {e}")
        return False

def test_gui_imports():
    """Test GUI module imports (without initializing GUI)"""
    try:
        from cybervault import gui
        
        # Test that the main function exists
        assert hasattr(gui, 'main'), "gui module should have main function"
        print("✓ gui module has main function")
        
        # Test that VaultGUI class can be imported
        from cybervault.gui import VaultGUI
        print("✓ VaultGUI class can be imported")
        
        # Test that key functions exist
        assert hasattr(gui, 'load_vault'), "gui module should have load_vault function"
        assert hasattr(gui, 'save_vault'), "gui module should have save_vault function"
        print("✓ gui module has required functions")
        
        return True
    except Exception as e:
        print(f"✗ GUI import test failed: {e}")
        return False

def test_tkinter_availability():
    """Test if Tkinter is available (but don't initialize GUI)"""
    try:
        import tkinter
        print("✓ Tkinter is available")
        return True
    except ImportError as e:
        print(f"⚠ Tkinter not available: {e}")
        return True  # This is not a failure, just a warning

def test_command_line_tools():
    """Test command line tools exist"""
    try:
        # Test that entry points are properly configured
        import subprocess
        import sys
        
        # Test vault command
        try:
            result = subprocess.run([sys.executable, "-m", "cybervault.vault", "--help"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ vault command works")
            else:
                print(f"⚠ vault command failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("⚠ vault command timed out")
            return False
        except FileNotFoundError:
            print("⚠ vault command not found")
            return False
            
        return True
    except Exception as e:
        print(f"✗ Command line test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing CyberVault package (headless mode)...")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_vault_functions,
        test_gui_imports,
        test_tkinter_availability,
        test_command_line_tools,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! Package is ready for distribution.")
        return 0
    else:
        print("❌ Some tests failed. Please check the package.")
        return 1

if __name__ == "__main__":
    exit(main()) 