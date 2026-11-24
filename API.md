# CloudDrift API Reference

## Python Library Usage

```python
from cloud_drift.core.state_parser import StateParser
from cloud_drift.engines.drift_detector import DriftDetector
from cloud_drift.engines.compliance import ComplianceEngine
from cloud_drift.engines.remediation import RemediationSynthesizer
from cloud_drift.reporters.cli_reporter import CLIReporter

# 1. Parse declared and live states
declared = StateParser.parse_declared_state("terraform.tfstate")
live = StateParser.parse_live_state("cloud_inventory.json")

# 2. Detect structural drift and shadow resources
drift_findings = DriftDetector.detect_drift(declared, live)

# 3. Detect out-of-band compliance degradations
compliance_findings = ComplianceEngine.audit_security_degradations(declared, live)
all_findings = drift_findings + compliance_findings

# 4. Synthesize remediations
remediations = RemediationSynthesizer.synthesize_remediations(all_findings, live)
```
