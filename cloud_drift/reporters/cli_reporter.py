"""
Console Summary Reporter for CloudDrift.
"""

from cloud_drift.core.models import CloudDriftReport


class CLIReporter:
    """Renders formatted terminal output for IaC drift and security compliance audits."""

    @staticmethod
    def print_summary(report: CloudDriftReport):
        print("\n" + "=" * 80)
        print("☁️  [CLOUDDRIFT] MULTI-CLOUD IAC DRIFT & SECURITY COMPLIANCE REPORT")
        print("=" * 80)
        print(f"  Declared State:          {report.declared_path} ({report.declared_count} resources)")
        print(f"  Live Cloud State:        {report.live_path} ({report.live_count} resources)")
        print(f"  Total Drift Findings:    {len(report.findings)}")
        print(f"  Remediations Generated:  {len(report.remediations)}")

        score_color = "🟢" if report.risk_score < 30 else ("🟡" if report.risk_score < 70 else "🔴")
        print(f"  Infrastructure Risk:     {score_color} {report.risk_score}/100")
        print("-" * 80)

        if not report.findings:
            print("  ✅ Infrastructure-as-Code is in 100% sync with live cloud state!")
        else:
            for idx, f in enumerate(report.findings, 1):
                badge = {
                    "CRITICAL": "💥 CRITICAL",
                    "HIGH": "🚨 HIGH    ",
                    "MEDIUM": "⚠️  MEDIUM  ",
                    "LOW": "ℹ️  LOW     ",
                }.get(f.severity, f.severity)

                print(f"[{idx:02d}] {badge} | {f.drift_type.value:<22} | {f.resource_type}.{f.resource_name}")
                print(f"     ID:          {f.resource_id}")
                print(f"     Issue:       {f.description}")
                if f.compliance_rule:
                    print(f"     Compliance:  {f.compliance_rule}")
                print()

        if report.remediations:
            print("🔧 SUGGESTED GITOPS REMEDIATION & IMPORTS:")
            for idx, r in enumerate(report.remediations, 1):
                print(f"  [{idx:02d}] {r.action_type:<16} | {r.summary}")
                if r.command:
                    print(f"       Command: {r.command}")

        print("\n" + "=" * 80 + "\n")
