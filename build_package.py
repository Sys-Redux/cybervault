#!/usr/bin/env python3
"""
Build script for CyberVault package
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return False

def clean_build():
    """Clean previous build artifacts"""
    print("🧹 Cleaning build artifacts...")
    dirs_to_clean = ['build', 'dist', '*.egg-info']
    for pattern in dirs_to_clean:
        if os.path.exists(pattern):
            import shutil
            shutil.rmtree(pattern)
    print("✅ Clean completed")

def build_package():
    """Build the package"""
    return run_command("python -m build", "Building package")

def check_package():
    """Check the built package"""
    return run_command("python -m twine check dist/*", "Checking package")

def main():
    """Main build process"""
    print("🚀 Starting CyberVault package build...")
    print("=" * 50)
    
    # Clean previous builds
    clean_build()
    
    # Build the package
    if not build_package():
        print("❌ Build failed!")
        return 1
    
    # Check the package
    if not check_package():
        print("❌ Package check failed!")
        return 1
    
    print("=" * 50)
    print("🎉 Package built successfully!")
    print("\n📦 Distribution files created in 'dist/' directory")
    print("\n📋 Next steps:")
    print("1. Test the package: pip install dist/cybervault-1.0.0.tar.gz")
    print("2. Upload to PyPI: python -m twine upload dist/*")
    print("3. Or upload to TestPyPI: python -m twine upload --repository testpypi dist/*")
    
    return 0

if __name__ == "__main__":
    exit(main()) 