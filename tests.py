import json
import tempfile
import unittest

from bitbucket import (
    load_trivy_report,
    parse_trivy_report,
    make_bitbucket_issues,
    make_bitbucket_report,
    write_bitbucket_report,
)


class TestLoadTrivyReport(unittest.TestCase):
    def test_ok(self):
        _, fname = tempfile.mkstemp()
        with open(fname, "w") as fobj:
            fobj.write('{"a":[]}')

        report = load_trivy_report(fname)
        assert report == {"a": []}

class TestWriteBitbucketReport(unittest.TestCase):
    def test_ok(self):
        _, fname = tempfile.mkstemp()
        report = {"a": []}
        write_bitbucket_report(json.dumps(report), fname)

        with open(fname) as fobj:
            assert json.loads(fobj.read()) == report


class TestParseTrivyReport(unittest.TestCase):
    def test_ok(self):
        vuln1 = {"field1": "value1"}
        vuln2 = {
            "VulnerabilityID": "vuln1",
            "Severity": "severity1",
            "Description": "desc1",
        }
        vuln3 = {
            "VulnerabilityID": "vuln2",
            "Severity": "severity2",
            "Description": "desc2",
        }
        report = {
            "Results": [
                {
                    "Target": "target1",
                    "Vulnerabilities": [
                        vuln1,
                        vuln2,
                    ],
                },
                {
                    "Target": "target2",
                    "Vulnerabilities": [
                        vuln3,
                    ],
                },
            ],
        }

        vulnerabilities = list(parse_trivy_report(report))
        assert vulnerabilities == [
            {
                "VulnerabilityID": "vuln1",
                "Severity": "severity1",
                "Description": "desc1",
                "Target": "target1",
            },
            {
                "VulnerabilityID": "vuln2",
                "Severity": "severity2",
                "Description": "desc2",
                "Target": "target2",
            },
        ]


class TestMakeBitbucketIssues(unittest.TestCase):
    def test_issue_formatting(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Severity": "LOW",
            "Description": "desc1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Severity": "MEDIUM",
            "Description": "desc2",
            "Target": "target2",
        }

        issues = make_bitbucket_issues([vuln1, vuln2])
        assert issues == [
            {
                "title": f"Issue (Severity: Low)",
                "type": "",
                "value": "desc1"
            },
            {
                "title": f"Issue (Severity: Medium)",
                "type": "",
                "value": "desc2"
            },
        ]


class TestMakeBitbucketReport(unittest.TestCase):
    def test_ok(self):
        issues = [1, True, "three"]
        report = make_bitbucket_report(issues)
        assert json.loads(report) == {
            "title": "Security scan report",
            "details": f"This pull request introduces 3 new dependency vulnerabilities.",
            "report_type": "SECURITY",
            "reporter": "Trivy",
            "result": "FAILED",
            "data": [1, True, "three"]
        }


if __name__ == "__main__":
    unittest.main()
