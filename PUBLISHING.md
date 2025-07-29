# Publishing CyberVault to PyPI

This guide will help you publish the CyberVault package to PyPI so others can install it with `pip install cybervault`.

## Prerequisites

1. **PyPI Account**: Create an account at [PyPI](https://pypi.org/account/register/)
2. **TestPyPI Account**: Create an account at [TestPyPI](https://test.pypi.org/account/register/)
3. **API Tokens**: Generate API tokens for both PyPI and TestPyPI

## Setup

### 1. Install Build Tools

```bash
pip install build twine
```

### 2. Configure Twine

Create a `~/.pypirc` file (or `%USERPROFILE%\.pypirc` on Windows):

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = your-pypi-api-token

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = your-testpypi-api-token
```

## Building the Package

### Option 1: Use the Build Script

```bash
python build_package.py
```

### Option 2: Manual Build

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python -m build

# Check the package
python -m twine check dist/*
```

## Testing on TestPyPI

Before publishing to PyPI, test on TestPyPI:

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ cybervault
```

## Publishing to PyPI

Once tested, publish to PyPI:

```bash
python -m twine upload dist/*
```

## Verifying the Installation

After publishing, test the installation:

```bash
# Install from PyPI
pip install cybervault

# Test the commands
vaultui --help
vault --help
```

## Version Management

To release a new version:

1. Update version in `setup.py` and `pyproject.toml`
2. Update version in `cybervault/__init__.py`
3. Build and publish as above

## GitHub Actions (Automated Publishing)

The `.github/workflows/python-package.yml` file is configured to automatically publish when you create a release on GitHub.

To use this:

1. Push your code to GitHub
2. Create a release with a tag (e.g., `v1.0.0`)
3. Add your PyPI API token as a GitHub secret named `PYPI_API_TOKEN`
4. The workflow will automatically build and publish

## Troubleshooting

### Common Issues

1. **"No module named 'cryptography'"**: Make sure cryptography is installed in your build environment
2. **"Invalid distribution"**: Check that your package structure is correct
3. **"Authentication failed"**: Verify your API tokens are correct

### Testing Locally

```bash
# Install in development mode
pip install -e .

# Test the commands
vaultui
vault --help
```

## Security Notes

- Never commit your API tokens to version control
- Use environment variables or secure configuration files
- Consider using GitHub Actions secrets for automated publishing

## Next Steps

After publishing:

1. Update the README.md with the correct PyPI installation instructions
2. Create a GitHub release with release notes
3. Share your package on social media and relevant communities
4. Monitor for issues and feedback

---

**Happy publishing! 🚀** 