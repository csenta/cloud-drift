import argparse
import os
import tempfile
import unittest
from cloud_drift.cli import handle_diff, handle_import, handle_remediate
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.decl_path = os.path.join(_ROOT, "examples", "declared_state.json")
        self.live_path = os.path.join(_ROOT, "examples", "live_cloud_state.json")

    def test_cli_diff(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f_json:
            out_json = f_json.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f_html:
            out_html = f_html.name

        try:
            args = argparse.Namespace(
                declared=self.decl_path,
                live=self.live_path,
                output_json=out_json,
                output_html=out_html,
                fail_on_severity=None,
            )
            code = handle_diff(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
        finally:
            for p in (out_json, out_html):
                if os.path.exists(p):
                    os.remove(p)

    def test_cli_import(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sh") as f_sh:
            out_sh = f_sh.name

        try:
            args = argparse.Namespace(
                declared=self.decl_path,
                live=self.live_path,
                output=out_sh,
            )
            code = handle_import(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_sh))
        finally:
            if os.path.exists(out_sh):
                os.remove(out_sh)

    def test_cli_remediate(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tf") as f_tf:
            out_tf = f_tf.name

        try:
            args = argparse.Namespace(
                declared=self.decl_path,
                live=self.live_path,
                output_hcl=out_tf,
            )
            code = handle_remediate(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_tf))
        finally:
            if os.path.exists(out_tf):
                os.remove(out_tf)


if __name__ == "__main__":
    unittest.main()
