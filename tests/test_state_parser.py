import os
import unittest
from cloud_drift.core.models import CloudProvider
from cloud_drift.core.state_parser import StateParser
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestStateParser(unittest.TestCase):
    def setUp(self):
        self.declared_path = os.path.join(_ROOT, "examples", "declared_state.json")
        self.live_path = os.path.join(_ROOT, "examples", "live_cloud_state.json")

    def test_parse_declared_state(self):
        self.assertTrue(os.path.isfile(self.declared_path))
        resources = StateParser.parse_declared_state(self.declared_path)
        self.assertEqual(len(resources), 3)

        self.assertIn("aws_security_group.web_sg", resources)
        self.assertIn("aws_s3_bucket.secure_vault", resources)
        self.assertIn("aws_ebs_volume.data_vol", resources)

        sg = resources["aws_security_group.web_sg"]
        self.assertEqual(sg.provider, CloudProvider.AWS)
        self.assertEqual(sg.resource_id, "sg-0123456789abcdef0")

    def test_parse_live_state(self):
        self.assertTrue(os.path.isfile(self.live_path))
        resources = StateParser.parse_live_state(self.live_path)
        self.assertEqual(len(resources), 4)
        self.assertIn("aws_s3_bucket.shadow_marketing_dump", resources)


if __name__ == "__main__":
    unittest.main()
