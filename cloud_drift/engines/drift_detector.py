"""
Differential IaC Drift and Shadow Resource Detector for CloudDrift.
"""

from typing import Any
import uuid

from cloud_drift.core.models import CloudResource, DriftFinding, DriftType


class DriftDetector:
    """Compares declared Terraform states against live cloud resource inventories."""

    @staticmethod
    def detect_drift(
        declared: dict[str, CloudResource],
        live: dict[str, CloudResource],
    ) -> list[DriftFinding]:
        findings: list[DriftFinding] = []

        # 1. Detect UNMANAGED / Shadow Resources (in live, not in declared)
        for live_key, live_res in live.items():
            if live_key not in declared:
                findings.append(
                    DriftFinding(
                        id=f"drift_{uuid.uuid4().hex[:8]}",
                        drift_type=DriftType.UNMANAGED_RESOURCE,
                        severity="HIGH",
                        resource_type=live_res.resource_type,
                        resource_name=live_res.resource_name,
                        resource_id=live_res.resource_id,
                        attribute_name="",
                        declared_value=None,
                        live_value=live_res.attributes,
                        description=f"Unmanaged cloud resource '{live_key}' (ID: {live_res.resource_id}) exists in live cloud but is completely missing from IaC state. Potential ClickOps shadow IT.",
                    )
                )

        # 2. Detect DELETED_IN_CLOUD Resources (in declared, not in live)
        for decl_key, decl_res in declared.items():
            if decl_key not in live:
                findings.append(
                    DriftFinding(
                        id=f"drift_{uuid.uuid4().hex[:8]}",
                        drift_type=DriftType.DELETED_IN_CLOUD,
                        severity="MEDIUM",
                        resource_type=decl_res.resource_type,
                        resource_name=decl_res.resource_name,
                        resource_id=decl_res.resource_id,
                        attribute_name="",
                        declared_value=decl_res.attributes,
                        live_value=None,
                        description=f"Declared resource '{decl_key}' is recorded in IaC state but was deleted out-of-band in the live cloud environment.",
                    )
                )

        # 3. Detect ATTRIBUTE_DRIFT (in both, but attributes differ)
        common_keys = set(declared.keys()).intersection(set(live.keys()))
        for key in common_keys:
            decl_res = declared[key]
            live_res = live[key]

            # Compare top-level attributes
            all_attrs = set(decl_res.attributes.keys()).union(set(live_res.attributes.keys()))
            for attr in all_attrs:
                # Ignore noisy meta attributes
                if attr in ("id", "arn", "tags_all", "self_link", "etag", "version_id"):
                    continue

                decl_val = decl_res.attributes.get(attr)
                live_val = live_res.attributes.get(attr)

                if decl_val is not None and live_val is not None:
                    if decl_val != live_val:
                        findings.append(
                            DriftFinding(
                                id=f"drift_{uuid.uuid4().hex[:8]}",
                                drift_type=DriftType.ATTRIBUTE_DRIFT,
                                severity="LOW",
                                resource_type=decl_res.resource_type,
                                resource_name=decl_res.resource_name,
                                resource_id=live_res.resource_id,
                                attribute_name=attr,
                                declared_value=decl_val,
                                live_value=live_val,
                                description=f"Attribute drift on '{key}.{attr}': declared as '{decl_val}', live value is '{live_val}'.",
                            )
                        )

        return findings
