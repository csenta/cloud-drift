import unittest
from cloud_drift.core.models import DriftType
from cloud_drift.core.state_parser import StateParser
from cloud_drift.engines.compliance import ComplianceEngine


class TestComplianceEngine(unittest.TestCase):
    def test_security_degradations(self):
        decl_path = "/home/emprogue/Projects/cloud-drift/examples/declared_state.json"
        live_path = "/home/emprogue/Projects/cloud-drift/examples/live_cloud_state.json"

        declared = StateParser.parse_declared_state(decl_path)
        live = StateParser.parse_live_state(live_path)

        findings = ComplianceEngine.audit_security_degradations(declared, live)
        rules = [f.compliance_rule for f in findings]

        # 1. Ingress 0.0.0.0/0 on port 22
        self.assertIn("CIS-AWS-4.1-OPEN-INGRESS", rules)

        # 2. S3 Public Access Block disabled
        self.assertIn("CIS-AWS-2.1.5-S3-PUBLIC-BLOCK", rules)

        # 3. S3 encryption disabled
        self.assertIn("CIS-AWS-2.1.1-S3-ENCRYPTION", rules)


if __name__ == "__main__":
    unittest.main()
