"""
Safe process inspection utilities.
"""

from typing import Optional

import psutil


def safe_process_info(pid: int) -> Optional[dict]:
    """
    Safely get process information without raising exceptions.

    Returns a dict with name, exe, username, cmdline, ppid, create_time,
    or None if the process doesn't exist or access is denied.
    """
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "username": proc.username(),
            "cmdline": proc.cmdline(),
            "ppid": proc.ppid(),
            "create_time": proc.create_time(),
            "status": proc.status(),
            "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def find_processes_by_name(name: str) -> list[dict]:
    """
    Find all running processes matching the given name (case-insensitive).

    Returns a list of process info dicts.
    """
    results = []
    name_lower = name.lower()

    for proc in psutil.process_iter(["name", "exe", "pid", "username"]):
        try:
            proc_name = proc.info.get("name", "")
            if proc_name and name_lower in proc_name.lower():
                info = safe_process_info(proc.info["pid"])
                if info:
                    results.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return results


def get_process_tree(pid: int) -> list[dict]:
    """
    Get the process tree (parent chain) for a given PID.

    Returns list from the target process up to init/System.
    """
    chain = []
    current_pid = pid

    while current_pid and current_pid != 0:
        info = safe_process_info(current_pid)
        if info is None:
            break
        chain.append(info)
        current_pid = info["ppid"]
        if current_pid in [p["pid"] for p in chain]:
            break  # Avoid loops

    return chain


def get_network_connections(pid: int) -> list[dict]:
    """Get all network connections for a specific process."""
    try:
        proc = psutil.Process(pid)
        connections = []
        for conn in proc.connections(kind="inet"):
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
            })
        return connections
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def get_loaded_modules(pid: int) -> list[str]:
    """Get list of loaded DLLs/shared libraries for a process."""
    try:
        proc = psutil.Process(pid)
        return [m.path for m in proc.memory_maps() if m.path]
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return []
