#!/usr/bin/env python3
"""
Simple test script for CyberVault package
"""

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
        
        return True
    except Exception as e:
        print(f"✗ Vault test failed: {e}")
        return False

def test_gui_functions():
    """Test basic GUI functionality"""
    try:
        from cybervault import gui
        
        # Test that the main function exists
        assert hasattr(gui, 'main'), "gui module should have main function"
        print("✓ gui module has main function")
        
        # Test that VaultGUI class can be imported
        from cybervault.gui import VaultGUI
        print("✓ VaultGUI class can be imported")
        
        return True
    except Exception as e:
        print(f"✗ GUI test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing CyberVault package...")
    print("=" * 40)
    
    tests = [
        test_imports,
        test_vault_functions,
        test_gui_functions,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("=" * 40)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! Package is ready for distribution.")
        return 0
    else:
        print("❌ Some tests failed. Please check the package.")
        return 1

if __name__ == "__main__":
    exit(main()) 