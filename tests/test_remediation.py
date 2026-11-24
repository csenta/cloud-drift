import unittest
from cloud_drift.core.models import DriftFinding, DriftType
from cloud_drift.engines.remediation import RemediationSynthesizer


class TestRemediation(unittest.TestCase):
    def test_synthesize_remediations(self):
        findings = [
            DriftFinding(
                id="f1",
                drift_type=DriftType.UNMANAGED_RESOURCE,
                severity="HIGH",
                resource_type="aws_s3_bucket",
                resource_name="shadow_bucket",
                resource_id="my-shadow-bucket",
                attribute_name="",
                declared_value=None,
                live_value={},
                description="Unmanaged bucket",
            ),
            DriftFinding(
                id="f2",
                drift_type=DriftType.SECURITY_DEGRADATION,
                severity="CRITICAL",
                resource_type="aws_security_group",
                resource_name="web_sg",
                resource_id="sg-12345",
                attribute_name="ingress",
                declared_value=None,
                live_value={},
                description="Open 0.0.0.0/0",
                compliance_rule="CIS-AWS-4.1-OPEN-INGRESS",
            ),
        ]

        actions = RemediationSynthesizer.synthesize_remediations(findings, {})
        action_types = [a.action_type for a in actions]

        self.assertIn("TERRAFORM_IMPORT", action_types)
        self.assertIn("HCL_PATCH", action_types)

        import_act = next(a for a in actions if a.action_type == "TERRAFORM_IMPORT")
        self.assertIn("terraform import aws_s3_bucket.shadow_bucket my-shadow-bucket", import_act.command)


if __name__ == "__main__":
    unittest.main()
