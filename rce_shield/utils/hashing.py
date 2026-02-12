"""
File hashing and integrity verification utilities.
"""

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Optional


def hash_file(filepath: str | Path, algorithm: str = "sha256") -> Optional[str]:
    """
    Compute the hash of a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')

    Returns:
        Hex digest string or None if file can't be read
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return None


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of raw bytes."""
    return hashlib.new(algorithm, data).hexdigest()


def verify_signature(filepath: str | Path) -> dict:
    """
    Verify the digital signature of a file.

    Returns a dict with:
        - signed: bool
        - valid: bool
        - signer: Optional[str]
        - error: Optional[str]
    """
    filepath = Path(filepath)

    if not filepath.exists():
        return {"signed": False, "valid": False, "signer": None, "error": "File not found"}

    if sys.platform == "win32":
        return _verify_windows_signature(filepath)
    elif sys.platform.startswith("linux"):
        return _verify_linux_signature(filepath)
    else:
        return {"signed": False, "valid": False, "signer": None, "error": "Unsupported platform"}


def _verify_windows_signature(filepath: Path) -> dict:
    """Verify Authenticode signature on Windows."""
    try:
        # Use PowerShell's Get-AuthenticodeSignature
        cmd = (
            f'powershell -Command "'
            f"$sig = Get-AuthenticodeSignature '{filepath}'; "
            f"$sig.Status; $sig.SignerCertificate.Subject"
            f'"'
        )
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            status = lines[0].strip() if lines else ""
            signer = lines[1].strip() if len(lines) > 1 else None

            return {
                "signed": status != "NotSigned",
                "valid": status == "Valid",
                "signer": signer,
                "error": None if status == "Valid" else f"Status: {status}",
            }
    except (subprocess.TimeoutExpired, OSError):
        pass

    return {"signed": False, "valid": False, "signer": None, "error": "Could not verify"}


def _verify_linux_signature(filepath: Path) -> dict:
    """Check ELF binary signatures on Linux."""
    # Check for GPG detached signature
    sig_path = filepath.with_suffix(filepath.suffix + ".sig")
    asc_path = filepath.with_suffix(filepath.suffix + ".asc")

    for sig in (sig_path, asc_path):
        if sig.exists():
            try:
                result = subprocess.run(
                    ["gpg", "--verify", str(sig), str(filepath)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    # Extract signer from GPG output
                    signer = None
                    for line in result.stderr.split("\n"):
                        if "Good signature from" in line:
                            signer = line.split('"')[1] if '"' in line else line
                    return {
                        "signed": True,
                        "valid": True,
                        "signer": signer,
                        "error": None,
                    }
                else:
                    return {
                        "signed": True,
                        "valid": False,
                        "signer": None,
                        "error": result.stderr.strip()[:200],
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    return {"signed": False, "valid": False, "signer": None, "error": "No signature found"}


def compare_hashes(file1: str | Path, file2: str | Path) -> bool:
    """Check if two files have identical content by comparing SHA-256 hashes."""
    h1 = hash_file(file1)
    h2 = hash_file(file2)
    if h1 is None or h2 is None:
        return False
    return h1 == h2
