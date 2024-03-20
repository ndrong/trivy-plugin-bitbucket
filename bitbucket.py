#!/usr/bin/env python3

import json
import os
import sys
import argparse


LOG_PREFIX = "[trivy][plugins][bitbucket]"
TRIVY_SEVERITY = {
    "UNKNOWN": "Unknown",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def load_trivy_report(fname):
    with open(fname) as fobj:
        return json.loads(fobj.read())


def write_bitbucket_report(report, file_path):
    with open(file_path, "w") as fobj:
        fobj.write(report)


def parse_trivy_report(report):
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            try:
                vuln["Target"] = result["Target"]
                for key in ("VulnerabilityID", "Severity", "Description"):
                    vuln[key]
            except KeyError:
                continue

            yield vuln


def make_bitbucket_issues(vulnerabilities):
    return [
        {
            "title": f"Issue (Severity: {TRIVY_SEVERITY[vuln['Severity']]})",
            "type": "TEXT",
            "value": vuln["Description"]
        }
        for vuln in vulnerabilities
    ]


def make_bitbucket_annotations(vulnerabilities):
    return [
        {
            "external_id": f"vuln-{idx + 1}",
            "title": f"{vuln['VulnerabilityID']} ({TRIVY_SEVERITY[vuln['Severity']]})",
            "annotation_type": "VULNERABILITY",
            "summary": vuln["Description"]
        }
        for idx, vuln in enumerate(vulnerabilities)
    ]


def make_bitbucket_report(issues):
    return json.dumps({
	"title": "Security scan report",
	"details": f"This pull request introduces {len(issues)} new dependency vulnerabilities." if len(issues) > 1 else f"This pull request introduces 1 new dependency vulnerability.",
	"report_type": "SECURITY",
	"reporter": "Trivy",
	"result": "FAILED",
	"data": issues
    }, indent=2)


def main(args):
    # Parse arguments using argparse
    if len(args) < 2:
        sys.exit(f"{LOG_PREFIX} missing required argument: <trivy-report.json>")

    parser = argparse.ArgumentParser(
                        prog='trivy-bitbucket')
    parser.add_argument('mode', type=str, help='Mode of operation (report, annotate)')
    parser.add_argument('fname', type=str, help='Trivy report file')
    parser.add_argument('file_path', type=str, help='Trivy report file')
    parser.add_argument('-o', '--output', type=str, help='Trivy report file')
    args = parser.parse_args()

    mode = args.mode
    if mode not in ['report', 'annotate']:
        sys.exit(f"{LOG_PREFIX} invalid mode: {mode}")

    fname = args.fname
    if not os.path.exists(fname):
        sys.exit(f"{LOG_PREFIX} file not found: {fname}")

    file_path = args.file_path if args.file_path else args.output

    report = load_trivy_report(fname)
    vulnerabilities = parse_trivy_report(report)

    if mode == "report":
        issues = make_bitbucket_issues(vulnerabilities)
        report = make_bitbucket_report(issues)
    elif mode == "annotate":
        issues = make_bitbucket_annotations(vulnerabilities)
        report = json.dumps(issues, indent=2)

    if file_path:
        write_bitbucket_report(report, file_path)
    print(report)


if __name__ == "__main__":
    main(sys.argv)
