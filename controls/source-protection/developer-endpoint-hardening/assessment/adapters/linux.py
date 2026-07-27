"""Collect sanitized Linux endpoint observations without changing host state."""

from __future__ import annotations

import grp
import os
import re
import shutil
import subprocess
from pathlib import Path


SIGNALS = {
    "credential_storage",
    "pre_commit_secret_scan",
    "sensitive_data_file_guard",
    "disk_encryption",
    "screen_lock",
    "automatic_updates",
    "local_admin",
    "docker_socket_exposed",
    "local_debug_services",
    "workspace_mount",
}
KNOWN_DEBUG_PORTS = {2345, 5005, 5678, 5858, 8787, 9229}
PRIVILEGED_GROUPS = {"admin", "sudo", "wheel"}
APPROVED_CREDENTIAL_HELPERS = {
    "libsecret",
    "manager",
    "manager-core",
    "osxkeychain",
    "secretservice",
    "wincred",
}


def _run(arguments: list[str], cwd: Path | None = None) -> tuple[int, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return result.returncode, result.stdout.strip()


def _credential_storage() -> str:
    code, output = _run(["git", "config", "--global", "--get-all", "credential.helper"])
    if code == 1:
        return "unknown"
    if code != 0:
        return "error"
    helpers = [line.strip().lower() for line in output.splitlines() if line.strip()]
    if not helpers:
        return "unknown"
    if any(helper == "store" or helper.startswith("store ") for helper in helpers):
        return "plaintext"
    if any(
        helper in APPROVED_CREDENTIAL_HELPERS
        or any(token in helper for token in ("1password", "libsecret", "manager-core"))
        for helper in helpers
    ):
        return "approved"
    return "unknown"


def _repository_guards(workspace: Path) -> tuple[str, str]:
    code, output = _run(["git", "config", "--get", "core.hooksPath"], cwd=workspace)
    if code == 1:
        return "disabled", "disabled"
    if code != 0 or not output:
        return "error", "error"
    hook_path = Path(output)
    if hook_path.is_absolute():
        return "disabled", "disabled"
    workspace_resolved = workspace.resolve()
    hooks_directory = (workspace / hook_path).resolve()
    try:
        hooks_directory.relative_to(workspace_resolved)
    except ValueError:
        return "disabled", "disabled"
    pre_commit = hooks_directory / "pre-commit"
    if not pre_commit.is_file():
        return "disabled", "disabled"
    try:
        hook_content = pre_commit.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "error", "error"
    pre_commit_status = "enabled"
    scanner = hooks_directory / "scan-sensitive.py"
    sensitive_guard = (
        "enabled"
        if "scan-sensitive" in hook_content and scanner.is_file()
        else "disabled"
    )
    return pre_commit_status, sensitive_guard


def _disk_encryption(workspace: Path) -> str:
    code, source = _run(["findmnt", "-n", "-o", "SOURCE", "--target", str(workspace)])
    if code != 0 or not source or not source.startswith("/dev/"):
        return "unknown"
    source = source.split("[", 1)[0]
    code, chain = _run(["lsblk", "-s", "-n", "-o", "TYPE,FSTYPE", source])
    if code != 0:
        return "unknown"
    lowered = chain.lower()
    if "crypt" in lowered or "crypto_luks" in lowered:
        return "enabled"
    return "disabled" if chain else "unknown"


def _screen_lock() -> str:
    if shutil.which("gsettings") is None:
        return "unknown"
    desktop = " ".join(
        (
            os.environ.get("XDG_CURRENT_DESKTOP", ""),
            os.environ.get("DESKTOP_SESSION", ""),
        )
    ).lower()
    if "gnome" not in desktop or not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return "unknown"
    lock_code, lock_enabled = _run(
        ["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"]
    )
    idle_code, idle_delay = _run(
        ["gsettings", "get", "org.gnome.desktop.session", "idle-delay"]
    )
    if lock_code != 0 or idle_code != 0:
        return "unknown"
    delay_match = re.search(r"(\d+)", idle_delay)
    if not delay_match:
        return "unknown"
    return (
        "enabled"
        if lock_enabled.strip().lower() == "true" and int(delay_match.group(1)) > 0
        else "disabled"
    )


def _automatic_updates() -> str:
    apt_policy = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt_policy.is_file():
        try:
            content = apt_policy.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "error"
        update_lists = re.search(
            r'APT::Periodic::Update-Package-Lists\s+"1"\s*;', content
        )
        unattended = re.search(
            r'APT::Periodic::Unattended-Upgrade\s+"1"\s*;', content
        )
        if update_lists and unattended:
            return "enabled"
        return "disabled"
    for unit in (
        "dnf-automatic.timer",
        "dnf5-automatic.timer",
        "rpm-ostreed-automatic.timer",
    ):
        code, output = _run(["systemctl", "is-enabled", unit])
        if code == 0 and output == "enabled":
            return "enabled"
    return "unknown"


def _local_admin() -> str:
    if os.geteuid() == 0:
        return "true"
    group_names = set()
    for group_id in {os.getgid(), *os.getgroups()}:
        try:
            group_names.add(grp.getgrgid(group_id).gr_name)
        except KeyError:
            continue
    return "true" if group_names & PRIVILEGED_GROUPS else "false"


def _docker_socket_exposed() -> str:
    docker_host = os.environ.get("DOCKER_HOST", "")
    if docker_host.lower().startswith(("tcp://", "http://", "https://")):
        return "true"
    sockets = [Path("/var/run/docker.sock"), Path("/run/podman/podman.sock")]
    existing = [path for path in sockets if path.exists()]
    if not existing:
        return "false"
    return "true" if any(os.access(path, os.W_OK) for path in existing) else "false"


def _local_debug_services() -> str:
    if shutil.which("ss") is None:
        return "unknown"
    code, output = _run(["ss", "-H", "-ltn"])
    if code != 0:
        return "error"
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        try:
            address, port_text = local.rsplit(":", 1)
            port = int(port_text)
        except (ValueError, TypeError):
            continue
        normalized = address.strip("[]")
        if port in KNOWN_DEBUG_PORTS and normalized not in {"127.0.0.1", "::1"}:
            return "enabled"
    return "disabled"


def _workspace_mount(workspace: Path) -> str:
    if not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists():
        return "unknown"
    code, output = _run(["findmnt", "-n", "-o", "OPTIONS", "--target", str(workspace)])
    if code != 0 or not output:
        return "unknown"
    options = {item.strip() for item in output.split(",")}
    if "ro" in options:
        return "read-only"
    if "rw" in options:
        return "read-write"
    return "unknown"


def collect(workspace: Path) -> dict[str, str]:
    """Return normalized signals only; never return raw host identifiers."""

    pre_commit, sensitive_guard = _repository_guards(workspace)
    observations = {
        "credential_storage": _credential_storage(),
        "pre_commit_secret_scan": pre_commit,
        "sensitive_data_file_guard": sensitive_guard,
        "disk_encryption": _disk_encryption(workspace),
        "screen_lock": _screen_lock(),
        "automatic_updates": _automatic_updates(),
        "local_admin": _local_admin(),
        "docker_socket_exposed": _docker_socket_exposed(),
        "local_debug_services": _local_debug_services(),
        "workspace_mount": _workspace_mount(workspace),
    }
    if set(observations) != SIGNALS:
        raise RuntimeError("Linux adapter returned an unexpected signal set")
    return observations
