#!/usr/bin/env python3

import json
import os
import sys

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
            "type": "",
            "value": vuln["Description"]
        }
        for vuln in vulnerabilities
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
    fname = args[1]
    if not os.path.exists(fname):
        sys.exit(f"{LOG_PREFIX} file not found: {fname}")

    # Specify optional output file path with flag -o
    file_path = None
    if len(args) > 3 and args[2] == "-o":
        file_path = args[3]

    report = load_trivy_report(fname)
    vulnerabilities = parse_trivy_report(report)
    issues = make_bitbucket_issues(vulnerabilities)
    report = make_bitbucket_report(issues)

    if file_path:
        write_bitbucket_report(report, file_path)
    print(report)


if __name__ == "__main__":
    main(sys.argv)
