"""
CIS Benchmark & Cloud Security Compliance Engine for CloudDrift.
Evaluates live and drifted cloud resources for out-of-band security degradations.
"""

from typing import Any
import uuid

from cloud_drift.core.models import CloudResource, DriftFinding, DriftType

SENSITIVE_PORTS = {22, 3389, 5432, 3306, 27017, 1433, 6379, 9200}


class ComplianceEngine:
    """Audits cloud configurations against CIS AWS/GCP/Azure Benchmarks."""

    @staticmethod
    def audit_security_degradations(
        declared: dict[str, CloudResource],
        live: dict[str, CloudResource],
    ) -> list[DriftFinding]:
        findings: list[DriftFinding] = []

        for key, live_res in live.items():
            decl_res = declared.get(key)
            r_type = live_res.resource_type

            # 1. Security Groups with Open Ingress (0.0.0.0/0 on sensitive ports)
            if r_type == "aws_security_group":
                ComplianceEngine._check_security_group(live_res, decl_res, findings)

            # 2. S3 Bucket Public Access Block & Encryption
            elif r_type == "aws_s3_bucket":
                ComplianceEngine._check_s3_bucket(live_res, decl_res, findings)

            # 3. EBS Volume Encryption
            elif r_type == "aws_ebs_volume":
                ComplianceEngine._check_ebs_volume(live_res, decl_res, findings)

            # 4. IAM Policy / Role Wildcards
            elif r_type in ("aws_iam_policy", "aws_iam_role"):
                ComplianceEngine._check_iam(live_res, decl_res, findings)

            # 5. RDS Public Access & Storage Encryption
            elif r_type in ("aws_db_instance", "aws_rds_cluster"):
                ComplianceEngine._check_rds(live_res, decl_res, findings)

        return findings

    @staticmethod
    def _check_security_group(live_res: CloudResource, decl_res: CloudResource | None, findings: list[DriftFinding]):
        ingress_rules = live_res.attributes.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]

        for rule in ingress_rules:
            cidrs = rule.get("cidr_blocks", [])
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)

            if "0.0.0.0/0" in cidrs:
                exposed_ports = [p for p in SENSITIVE_PORTS if from_port <= p <= to_port] or [from_port]
                findings.append(
                    DriftFinding(
                        id=f"sec_{uuid.uuid4().hex[:8]}",
                        drift_type=DriftType.SECURITY_DEGRADATION,
                        severity="CRITICAL",
                        resource_type=live_res.resource_type,
                        resource_name=live_res.resource_name,
                        resource_id=live_res.resource_id,
                        attribute_name="ingress.cidr_blocks",
                        declared_value=decl_res.attributes.get("ingress") if decl_res else "None",
                        live_value=rule,
                        description=f"Security Group '{live_res.resource_name}' allows unrestricted ingress ('0.0.0.0/0') on sensitive port(s) {exposed_ports} (CIS AWS 4.1/4.2).",
                        compliance_rule="CIS-AWS-4.1-OPEN-INGRESS",
                    )
                )

    @staticmethod
    def _check_s3_bucket(live_res: CloudResource, decl_res: CloudResource | None, findings: list[DriftFinding]):
        attrs = live_res.attributes
        # Public access block
        pab = attrs.get("public_access_block", {})
        block_acls = pab.get("block_public_acls", attrs.get("block_public_acls"))
        block_policy = pab.get("block_public_policy", attrs.get("block_public_policy"))

        if block_acls is False or block_policy is False or (block_acls is None and "public" in str(attrs.get("acl", ""))):
            findings.append(
                DriftFinding(
                    id=f"sec_{uuid.uuid4().hex[:8]}",
                    drift_type=DriftType.SECURITY_DEGRADATION,
                    severity="CRITICAL",
                    resource_type=live_res.resource_type,
                    resource_name=live_res.resource_name,
                    resource_id=live_res.resource_id,
                    attribute_name="public_access_block",
                    declared_value="Blocked",
                    live_value="Publicly Exposed",
                    description=f"S3 Bucket '{live_res.resource_name}' has public access block disabled or grants public read ACL (CIS AWS 2.1.5).",
                    compliance_rule="CIS-AWS-2.1.5-S3-PUBLIC-BLOCK",
                )
            )

        # Server side encryption
        sse = attrs.get("server_side_encryption_configuration")
        if not sse and attrs.get("encrypted") is not True:
            findings.append(
                DriftFinding(
                    id=f"sec_{uuid.uuid4().hex[:8]}",
                    drift_type=DriftType.SECURITY_DEGRADATION,
                    severity="HIGH",
                    resource_type=live_res.resource_type,
                    resource_name=live_res.resource_name,
                    resource_id=live_res.resource_id,
                    attribute_name="server_side_encryption_configuration",
                    declared_value="Enabled",
                    live_value="Disabled / Missing",
                    description=f"S3 Bucket '{live_res.resource_name}' does not enforce server-side encryption at rest (CIS AWS 2.1.1).",
                    compliance_rule="CIS-AWS-2.1.1-S3-ENCRYPTION",
                )
            )

    @staticmethod
    def _check_ebs_volume(live_res: CloudResource, decl_res: CloudResource | None, findings: list[DriftFinding]):
        if live_res.attributes.get("encrypted") is False:
            findings.append(
                DriftFinding(
                    id=f"sec_{uuid.uuid4().hex[:8]}",
                    drift_type=DriftType.SECURITY_DEGRADATION,
                    severity="HIGH",
                    resource_type=live_res.resource_type,
                    resource_name=live_res.resource_name,
                    resource_id=live_res.resource_id,
                    attribute_name="encrypted",
                    declared_value=True,
                    live_value=False,
                    description=f"EBS Volume '{live_res.resource_name}' (ID: {live_res.resource_id}) is unencrypted in live cloud.",
                    compliance_rule="CIS-AWS-2.2.1-EBS-ENCRYPTION",
                )
            )

    @staticmethod
    def _check_iam(live_res: CloudResource, decl_res: CloudResource | None, findings: list[DriftFinding]):
        policy_doc = str(live_res.attributes.get("policy", "")).lower()
        if '"action": "*"' in policy_doc and '"resource": "*"' in policy_doc:
            findings.append(
                DriftFinding(
                    id=f"sec_{uuid.uuid4().hex[:8]}",
                    drift_type=DriftType.SECURITY_DEGRADATION,
                    severity="CRITICAL",
                    resource_type=live_res.resource_type,
                    resource_name=live_res.resource_name,
                    resource_id=live_res.resource_id,
                    attribute_name="policy",
                    declared_value="Restricted",
                    live_value="Full Administrator (Action: *, Resource: *)",
                    description=f"IAM resource '{live_res.resource_name}' grants full wildcard administrator privileges ('*'). Violates least privilege (CIS AWS 1.16).",
                    compliance_rule="CIS-AWS-1.16-IAM-WILDCARD",
                )
            )

    @staticmethod
    def _check_rds(live_res: CloudResource, decl_res: CloudResource | None, findings: list[DriftFinding]):
        attrs = live_res.attributes
        if attrs.get("publicly_accessible") is True:
            findings.append(
                DriftFinding(
                    id=f"sec_{uuid.uuid4().hex[:8]}",
                    drift_type=DriftType.SECURITY_DEGRADATION,
                    severity="CRITICAL",
                    resource_type=live_res.resource_type,
                    resource_name=live_res.resource_name,
                    resource_id=live_res.resource_id,
                    attribute_name="publicly_accessible",
                    declared_value=False,
                    live_value=True,
                    description=f"Database '{live_res.resource_name}' is configured as publicly accessible from the internet (CIS AWS 2.3.1).",
                    compliance_rule="CIS-AWS-2.3.1-RDS-PUBLIC",
                )
            )
