import unittest
from cloud_drift.core.models import DriftType
from cloud_drift.core.state_parser import StateParser
from cloud_drift.engines.drift_detector import DriftDetector


class TestDriftDetector(unittest.TestCase):
    def test_drift_detection(self):
        decl_path = "/home/emprogue/Projects/cloud-drift/examples/declared_state.json"
        live_path = "/home/emprogue/Projects/cloud-drift/examples/live_cloud_state.json"

        declared = StateParser.parse_declared_state(decl_path)
        live = StateParser.parse_live_state(live_path)

        findings = DriftDetector.detect_drift(declared, live)
        drift_types = [f.drift_type for f in findings]

        # 1. Unmanaged shadow S3 bucket found
        self.assertIn(DriftType.UNMANAGED_RESOURCE, drift_types)
        unmanaged = next(f for f in findings if f.drift_type == DriftType.UNMANAGED_RESOURCE)
        self.assertEqual(unmanaged.resource_name, "shadow_marketing_dump")

        # 2. Attribute drift found on description/ingress
        self.assertIn(DriftType.ATTRIBUTE_DRIFT, drift_types)


if __name__ == "__main__":
    unittest.main()
