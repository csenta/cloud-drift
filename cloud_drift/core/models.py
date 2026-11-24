"""
Domain Data Models for CloudDrift.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    GENERIC = "generic"


class DriftType(str, Enum):
    UNMANAGED_RESOURCE = "UNMANAGED_RESOURCE"
    DELETED_IN_CLOUD = "DELETED_IN_CLOUD"
    ATTRIBUTE_DRIFT = "ATTRIBUTE_DRIFT"
    SECURITY_DEGRADATION = "SECURITY_DEGRADATION"


@dataclass
class CloudResource:
    provider: CloudProvider
    resource_type: str  # e.g., aws_security_group, aws_s3_bucket
    resource_name: str  # e.g., web_ingress, data_vault
    resource_id: str  # e.g., sg-01234567, arn:aws:s3:::vault
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "declared"  # declared or live

    @property
    def key(self) -> str:
        return f"{self.resource_type}.{self.resource_name}"


@dataclass
class DriftFinding:
    id: str
    drift_type: DriftType
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    resource_type: str
    resource_name: str
    resource_id: str
    attribute_name: str
    declared_value: Any
    live_value: Any
    description: str
    compliance_rule: str = ""


@dataclass
class RemediationAction:
    resource_type: str
    resource_name: str
    resource_id: str
    action_type: str  # HCL_PATCH, TERRAFORM_IMPORT, CLI_REVERSAL
    summary: str
    patch_content: str = ""
    command: str = ""


@dataclass
class CloudDriftReport:
    declared_path: str
    live_path: str
    declared_count: int
    live_count: int
    findings: list[DriftFinding] = field(default_factory=list)
    remediations: list[RemediationAction] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared_path": self.declared_path,
            "live_path": self.live_path,
            "declared_count": self.declared_count,
            "live_count": self.live_count,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "drift_type": f.drift_type.value,
                    "severity": f.severity,
                    "resource": f"{f.resource_type}.{f.resource_name}",
                    "resource_id": f.resource_id,
                    "attribute": f.attribute_name,
                    "declared": f.declared_value,
                    "live": f.live_value,
                    "description": f.description,
                    "compliance": f.compliance_rule,
                }
                for f in self.findings
            ],
            "remediations_count": len(self.remediations),
        }
