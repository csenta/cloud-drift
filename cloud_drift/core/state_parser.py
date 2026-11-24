"""
Terraform State and Cloud Snapshot Parser for CloudDrift.
Ingests Terraform State v4, plan JSONs, and live cloud resource exports.
"""

import json
import os
from typing import Any
import yaml

from cloud_drift.core.models import CloudProvider, CloudResource


class StateParser:
    """Parses declared Terraform states and live cloud snapshot inventories."""

    @staticmethod
    def parse_declared_state(file_path: str) -> dict[str, CloudResource]:
        """Parses terraform.tfstate or declared JSON into CloudResource map."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Declared state file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = yaml.safe_load(content)

        return StateParser._parse_state_data(data, source="declared")

    @staticmethod
    def parse_live_state(file_path: str) -> dict[str, CloudResource]:
        """Parses live cloud snapshot inventory into CloudResource map."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Live cloud state file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = yaml.safe_load(content)

        return StateParser._parse_state_data(data, source="live")

    @staticmethod
    def _detect_provider(res_type: str) -> CloudProvider:
        res_lower = res_type.lower()
        if res_lower.startswith("aws_"):
            return CloudProvider.AWS
        elif res_lower.startswith("azurerm_") or res_lower.startswith("azure_"):
            return CloudProvider.AZURE
        elif res_lower.startswith("google_") or res_lower.startswith("gcp_"):
            return CloudProvider.GCP
        elif res_lower.startswith("kubernetes_"):
            return CloudProvider.KUBERNETES
        return CloudProvider.GENERIC

    @staticmethod
    def _parse_state_data(data: Any, source: str) -> dict[str, CloudResource]:
        resources: dict[str, CloudResource] = {}

        # 1. Standard Terraform State v4 ({"version": 4, "resources": [...]})
        if isinstance(data, dict) and "resources" in data and isinstance(data["resources"], list):
            for res_entry in data["resources"]:
                r_type = res_entry.get("type", "")
                r_name = res_entry.get("name", "")
                provider = StateParser._detect_provider(r_type)

                for inst in res_entry.get("instances", []):
                    attrs = inst.get("attributes", {})
                    r_id = attrs.get("id") or attrs.get("arn") or f"{r_type}_{r_name}"
                    cr = CloudResource(
                        provider=provider,
                        resource_type=r_type,
                        resource_name=r_name,
                        resource_id=r_id,
                        attributes=attrs,
                        source=source,
                    )
                    resources[cr.key] = cr

        # 2. Simplified Resource List / Cloud Inventory ([{type, name, attributes...}])
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    r_type = item.get("resource_type") or item.get("type", "unknown")
                    r_name = item.get("resource_name") or item.get("name", "unnamed")
                    attrs = item.get("attributes") or item
                    r_id = item.get("resource_id") or attrs.get("id") or f"{r_type}_{r_name}"
                    provider = StateParser._detect_provider(r_type)

                    cr = CloudResource(
                        provider=provider,
                        resource_type=r_type,
                        resource_name=r_name,
                        resource_id=r_id,
                        attributes=attrs,
                        source=source,
                    )
                    resources[cr.key] = cr

        # 3. Direct Dictionary mapping resource_key -> attributes
        elif isinstance(data, dict):
            for k, val in data.items():
                if isinstance(val, dict):
                    parts = k.split(".", 1)
                    r_type = parts[0]
                    r_name = parts[1] if len(parts) > 1 else "default"
                    attrs = val.get("attributes", val)
                    r_id = attrs.get("id", k)
                    provider = StateParser._detect_provider(r_type)

                    cr = CloudResource(
                        provider=provider,
                        resource_type=r_type,
                        resource_name=r_name,
                        resource_id=r_id,
                        attributes=attrs,
                        source=source,
                    )
                    resources[cr.key] = cr

        return resources
