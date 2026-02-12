"""
Platform detection and OS-specific utilities.
"""

import os
import platform
import sys
from dataclasses import dataclass


@dataclass
class PlatformInfo:
    """System platform information."""
    os_name: str          # 'windows', 'linux', 'darwin'
    os_version: str       # e.g. '10.0.19041'
    architecture: str     # 'x86_64', 'aarch64'
    hostname: str
    is_admin: bool
    python_version: str
    kernel: str           # Linux kernel or Windows build


def get_platform_info() -> PlatformInfo:
    """Gather comprehensive platform information."""
    os_name = sys.platform
    if os_name.startswith("linux"):
        os_name = "linux"
    elif os_name == "win32":
        os_name = "windows"
    elif os_name == "darwin":
        os_name = "darwin"

    kernel = platform.release()

    return PlatformInfo(
        os_name=os_name,
        os_version=platform.version(),
        architecture=platform.machine(),
        hostname=platform.node(),
        is_admin=is_admin(),
        python_version=platform.python_version(),
        kernel=kernel,
    )


def is_admin() -> bool:
    """Check if running with elevated (root/admin) privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        return os.geteuid() == 0


def get_home_dir() -> str:
    """Get the user's home directory."""
    return os.path.expanduser("~")


def get_appdata_dir() -> str:
    """Get the application data directory (cross-platform)."""
    if sys.platform == "win32":
        return os.environ.get("APPDATA", os.path.expanduser("~"))
    elif sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        return os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))


def get_temp_dir() -> str:
    """Get the system temp directory."""
    import tempfile
    return tempfile.gettempdir()
