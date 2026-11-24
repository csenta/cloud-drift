# Security Policy

## Security Model

CloudDrift performs offline static and state comparisons between Infrastructure-as-Code state definitions and exported cloud inventories.

### Safe by Design
- **Offline Operation**: Performs state diffing locally without sending cloud state data or access credentials to external endpoints.
- **Credential Safety**: Never prints, logs, or stores unencrypted cloud credentials.

## Reporting a Vulnerability

If you identify a security defect in CloudDrift:
1. Do not open public GitHub issues.
2. Submit details to the repository maintainers through private GitHub security advisories.
