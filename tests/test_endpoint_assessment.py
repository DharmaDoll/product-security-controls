from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ADAPTER_PATH = (
    REPOSITORY_ROOT
    / "controls"
    / "source-protection"
    / "developer-endpoint-hardening"
    / "assessment"
    / "adapters"
    / "linux.py"
)
SPEC = importlib.util.spec_from_file_location("endpoint_linux", ADAPTER_PATH)
assert SPEC and SPEC.loader
endpoint_linux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(endpoint_linux)


class LinuxEndpointAdapterTest(unittest.TestCase):
    def test_plaintext_credential_helper_is_rejected(self) -> None:
        with mock.patch.object(endpoint_linux, "_run", return_value=(0, "store")):
            self.assertEqual(endpoint_linux._credential_storage(), "plaintext")

    def test_approved_credential_helper_is_recognized(self) -> None:
        with mock.patch.object(
            endpoint_linux, "_run", return_value=(0, "manager-core")
        ):
            self.assertEqual(endpoint_linux._credential_storage(), "approved")

    def test_repository_guards_require_relative_reviewed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            hooks = workspace / ".githooks"
            hooks.mkdir()
            (hooks / "pre-commit").write_text(
                "python3 .githooks/scan-sensitive.py --staged\n",
                encoding="utf-8",
            )
            (hooks / "scan-sensitive.py").write_text("# fixture\n", encoding="utf-8")
            with mock.patch.object(
                endpoint_linux, "_run", return_value=(0, ".githooks")
            ):
                self.assertEqual(
                    endpoint_linux._repository_guards(workspace),
                    ("enabled", "enabled"),
                )

    def test_absolute_hook_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                endpoint_linux, "_run", return_value=(0, "/shared/hooks")
            ):
                self.assertEqual(
                    endpoint_linux._repository_guards(Path(temporary)),
                    ("disabled", "disabled"),
                )

    def test_known_non_loopback_debug_listener_is_detected(self) -> None:
        output = "LISTEN 0 128 0.0.0.0:9229 0.0.0.0:*"
        with (
            mock.patch.object(endpoint_linux.shutil, "which", return_value="/bin/ss"),
            mock.patch.object(endpoint_linux, "_run", return_value=(0, output)),
        ):
            self.assertEqual(endpoint_linux._local_debug_services(), "enabled")

    def test_loopback_debug_listener_is_not_reported(self) -> None:
        output = "LISTEN 0 128 127.0.0.1:9229 0.0.0.0:*"
        with (
            mock.patch.object(endpoint_linux.shutil, "which", return_value="/bin/ss"),
            mock.patch.object(endpoint_linux, "_run", return_value=(0, output)),
        ):
            self.assertEqual(endpoint_linux._local_debug_services(), "disabled")

    def test_inaccessible_block_device_is_unresolved_not_error(self) -> None:
        with mock.patch.object(
            endpoint_linux,
            "_run",
            side_effect=[
                (0, "/dev/sdc[/workspace]"),
                (32, ""),
            ],
        ):
            self.assertEqual(
                endpoint_linux._disk_encryption(Path("/workspace")),
                "unknown",
            )

    def test_screen_lock_requires_active_gnome_session(self) -> None:
        with (
            mock.patch.object(endpoint_linux.shutil, "which", return_value="/bin/gsettings"),
            mock.patch.dict(endpoint_linux.os.environ, {}, clear=True),
        ):
            self.assertEqual(endpoint_linux._screen_lock(), "unknown")


if __name__ == "__main__":
    unittest.main()
