"""
CyberVault - A secure encrypted notes vault with cyberpunk-themed GUI

A Python package for securely storing and managing encrypted notes with a beautiful
cyberpunk-themed graphical user interface.
"""

__version__ = "1.0.0"
__author__ = "Layzee"
__description__ = "A secure encrypted notes vault with cyberpunk-themed GUI"

from . import vault
from . import gui

__all__ = ["vault", "gui"] 