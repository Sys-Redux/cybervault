from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    return ""

setup(
    name="cybervault",
    version="1.0.0",
    author="Layzee",
    author_email="",
    description="A secure encrypted notes vault with cyberpunk-themed GUI",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cybervault",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
    install_requires=[
        "cryptography>=3.4.0",
    ],
    entry_points={
        "console_scripts": [
            "vaultui=cybervault.gui:main",
            "vault=cybervault.vault:main",
        ],
    },
    include_package_data=True,
    keywords="encryption, security, password-manager, notes, vault, cyberpunk",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/cybervault/issues",
        "Source": "https://github.com/yourusername/cybervault",
    },
) 