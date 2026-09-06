from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class RunControlsTest(unittest.TestCase):
    def test_selected_manual_control_is_not_reported_as_verified(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/run-controls.py",
                "--control",
                "PSB-CICD-004",
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("NOT_CHECKED PSB-CICD-004", result.stdout)
        self.assertIn("verified 0 control(s); 1 control(s) NOT_CHECKED", result.stdout)


if __name__ == "__main__":
    unittest.main()
