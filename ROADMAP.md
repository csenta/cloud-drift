# CloudDrift Roadmap

## Phase 1: State Ingestion & Resource Graph (Completed)
- [x] Ingestion parser for Terraform State v4 and live cloud resource exports.
- [x] Normalized multi-cloud resource schema model (AWS, Azure, GCP).
- [x] Recursive attribute diffing engine.

## Phase 2: Drift & Security Analysis (Completed)
- [x] Unmanaged / shadow cloud resource discovery.
- [x] Attribute mutation & out-of-band ClickOps drift detection.
- [x] CIS Benchmark security rules engine (S3, Security Groups, IAM, RDS, EBS).

## Phase 3: Automated Remediation & CI/CD (Completed)
- [x] GitOps HCL patch synthesizer.
- [x] `terraform import` script generator for unmanaged resources.
- [x] CLI interface with `scan`, `diff`, `remediate`, and `import`.
- [x] Interactive HTML5 executive dashboard and CI quality gate.
- [x] Containerization and automated GitHub Actions verification.
