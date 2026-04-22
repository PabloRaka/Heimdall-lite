import os
import shlex
import subprocess
from pathlib import Path


HOST_DEFENSE_MODE = os.getenv("HEIMDALL_HOST_DEFENSE", "0").lower() in {"1", "true", "yes", "on"}
HOST_ROOT = os.getenv("HEIMDALL_HOST_ROOT", "/host")
USE_NSENTER = os.getenv("HEIMDALL_USE_NSENTER", "1").lower() in {"1", "true", "yes", "on"}
DISABLE_SUDO = os.getenv("HEIMDALL_DISABLE_SUDO", "1").lower() in {"1", "true", "yes", "on"}


def needs_sudo() -> bool:
    return os.geteuid() != 0 and not DISABLE_SUDO


def maybe_sudo(command: str) -> str:
    if not command or not needs_sudo():
        return command
    if command.lstrip().startswith("sudo "):
        return command
    return f"sudo {command}"


def host_path(path: str) -> str:
    if not path.startswith("/"):
        return path
    if HOST_DEFENSE_MODE and HOST_ROOT not in {"", "/"}:
        return str(Path(HOST_ROOT) / path.lstrip("/"))
    return path


def host_command(command: str, *, use_nsenter: bool = True, sudo: bool = False) -> str:
    wrapped = maybe_sudo(command) if sudo else command
    if HOST_DEFENSE_MODE and USE_NSENTER and use_nsenter:
        return f"nsenter -t 1 -m -u -n -i sh -lc {shlex.quote(wrapped)}"
    return wrapped


def run_host_command(command: str, *, timeout: int = 15, sudo: bool = False, use_nsenter: bool = True):
    return subprocess.run(
        host_command(command, use_nsenter=use_nsenter, sudo=sudo),
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def host_path_exists(path: str) -> bool:
    if HOST_DEFENSE_MODE and USE_NSENTER:
        result = run_host_command(f"test -e {shlex.quote(path)} && echo EXISTS", timeout=5)
        return "EXISTS" in (result.stdout or "")
    return Path(host_path(path)).exists()
