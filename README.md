# CyberVault 🔐

A secure encrypted notes vault with a beautiful cyberpunk-themed graphical user interface. Store your sensitive information with military-grade encryption in a sleek, futuristic interface.

## Features

- 🔒 **Military-grade encryption** using Fernet (AES-128-CBC)
- 🎨 **Cyberpunk-themed GUI** with neon colors and futuristic design
- 🔐 **Master password protection** with secure password hashing
- 📝 **Rich text editing** for your encrypted notes
- 🗂️ **Organized note management** with titles and content
- 💾 **Automatic saving** of encrypted data
- 🚀 **Cross-platform** - works on Windows, macOS, and Linux (CI tested on Ubuntu and macOS)

## Installation

### From PyPI (Recommended)

```bash
pip install cybervault
```

### From Source

```bash
git clone https://github.com/Sys-Redux/cybervault.git
cd cybervault
pip install -e .
```

## Usage

### GUI Mode (Recommended)

Launch the cyberpunk-themed graphical interface:

```bash
vaultui
```

### Command Line Mode

For advanced users who prefer the command line:

```bash
# Add a new note
vault add --title "My Secret Note" --text "This is my encrypted content"

# Retrieve a note
vault get --title "My Secret Note"

# List all notes
vault list

# Delete a note
vault delete --title "My Secret Note"
```

## Security Features

- **PBKDF2 Key Derivation**: Uses 390,000 iterations for key derivation
- **Fernet Encryption**: AES-128-CBC encryption with HMAC authentication
- **Secure Password Hashing**: 200,000 iterations for master password storage
- **Salt Generation**: Unique salt for each vault and password hash
- **No Plaintext Storage**: All sensitive data is encrypted before storage

## File Storage

Your encrypted vault is stored in your home directory:
- **Vault data**: `~/vault.json`
- **Master password hash**: `~/master.hash`

## First Time Setup

1. Run `vaultui` to launch the application
2. Set your master password when prompted
3. Start adding your encrypted notes!

## Requirements

- Python 3.7 or higher
- `cryptography` library
- `tkinter` (usually included with Python)

### GUI Requirements

The GUI mode (`vaultui`) requires a graphical display environment. If you're running on a headless server or in a container without a display, you can still use the command-line mode (`vault`).

## Development

To contribute to CyberVault:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and personal use. While it uses strong encryption, the authors make no guarantees about security. Use at your own risk.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any issues or have questions, please open an issue on GitHub.

---

**Stay secure in the digital age with CyberVault!** 🔐✨ 
