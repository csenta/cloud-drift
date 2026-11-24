"""
Automated GitOps HCL Patch and Terraform Import Synthesizer for CloudDrift.
"""

from cloud_drift.core.models import CloudResource, DriftFinding, DriftType, RemediationAction


class RemediationSynthesizer:
    """Generates hardened Terraform HCL blocks and automated import scripts."""

    @staticmethod
    def synthesize_remediations(
        findings: list[DriftFinding],
        live: dict[str, CloudResource],
    ) -> list[RemediationAction]:
        actions: list[RemediationAction] = []

        for f in findings:
            if f.drift_type == DriftType.UNMANAGED_RESOURCE:
                import_cmd = f"terraform import {f.resource_type}.{f.resource_name} {f.resource_id}"
                hcl_stub = f"""resource "{f.resource_type}" "{f.resource_name}" {{
  # Managed by Terraform via CloudDrift import
  # Resource ID: {f.resource_id}
}}"""
                actions.append(
                    RemediationAction(
                        resource_type=f.resource_type,
                        resource_name=f.resource_name,
                        resource_id=f.resource_id,
                        action_type="TERRAFORM_IMPORT",
                        summary=f"Import unmanaged {f.resource_type} into Terraform state",
                        patch_content=hcl_stub,
                        command=import_cmd,
                    )
                )

            elif f.drift_type == DriftType.SECURITY_DEGRADATION:
                if f.compliance_rule == "CIS-AWS-4.1-OPEN-INGRESS":
                    reversal_cmd = f"aws ec2 revoke-security-group-ingress --group-id {f.resource_id} --protocol tcp --port 22 --cidr 0.0.0.0/0"
                    hcl_patch = f"""# Replace open 0.0.0.0/0 ingress with corporate VPN CIDR
resource "{f.resource_type}" "{f.resource_name}" {{
  ingress {{
    description = "Restricted Corporate Ingress"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Replace with authorized bastion/VPN CIDR
  }}
}}"""
                    actions.append(
                        RemediationAction(
                            resource_type=f.resource_type,
                            resource_name=f.resource_name,
                            resource_id=f.resource_id,
                            action_type="HCL_PATCH",
                            summary="Harden open security group ingress rule",
                            patch_content=hcl_patch,
                            command=reversal_cmd,
                        )
                    )

                elif f.compliance_rule == "CIS-AWS-2.1.5-S3-PUBLIC-BLOCK":
                    hcl_patch = f"""resource "aws_s3_bucket_public_access_block" "{f.resource_name}_pab" {{
  bucket = "{f.resource_id}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"""
                    actions.append(
                        RemediationAction(
                            resource_type=f.resource_type,
                            resource_name=f.resource_name,
                            resource_id=f.resource_id,
                            action_type="HCL_PATCH",
                            summary="Enforce S3 bucket public access block",
                            patch_content=hcl_patch,
                            command=f"aws s3api put-public-access-block --bucket {f.resource_id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        )
                    )

                elif f.compliance_rule == "CIS-AWS-2.1.1-S3-ENCRYPTION":
                    hcl_patch = f"""resource "aws_s3_bucket_server_side_encryption_configuration" "{f.resource_name}_sse" {{
  bucket = "{f.resource_id}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"""
                    actions.append(
                        RemediationAction(
                            resource_type=f.resource_type,
                            resource_name=f.resource_name,
                            resource_id=f.resource_id,
                            action_type="HCL_PATCH",
                            summary="Enable S3 bucket default AES256 server-side encryption",
                            patch_content=hcl_patch,
                            command=f"aws s3api put-bucket-encryption --bucket {f.resource_id} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                        )
                    )

        return actions
