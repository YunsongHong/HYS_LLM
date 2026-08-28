import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


class AssistedUiTests(unittest.TestCase):
    def test_async_context_upload_and_pagination_regressions(self):
        node = os.environ.get("PARAMGUARD_NODE_BINARY") or shutil.which("node")
        if not node:
            self.skipTest(
                "Node not available; run tools/check_assisted_ui.mjs separately"
            )
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [node, str(root / "tools/check_assisted_ui.mjs")],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("assisted UI async regression checks passed", result.stdout)

    def test_default_web_entry_does_not_import_assisted_state(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import paramguard.webapp; assert 'paramguard.assisted' not in sys.modules; assert 'paramguard.assisted_web' not in sys.modules",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
