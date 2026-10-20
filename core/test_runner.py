"""
Automated pytest & unittest programmatic runner for backend APIs and RAG pipelines.
Captures structured JSON test reports with pass/fail, latency, traceback, confidence scores.
"""

import json
import os
import sys
import time
import traceback
import unittest
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TestCaseResult:
    """Single test-case outcome."""
    test_id: str
    test_name: str
    module: str
    category: str  # unit | integration | edge_case
    status: str  # passed | failed | error | skipped
    duration_ms: float = 0.0
    traceback_str: Optional[str] = None
    stdout: Optional[str] = None
    confidence_score: Optional[float] = None  # RAG-specific
    metadata: dict = field(default_factory=dict)


@dataclass
class TestSuiteReport:
    """Aggregate report for an entire test run."""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    total_duration_ms: float = 0.0
    results: list[TestCaseResult] = field(default_factory=list)
    summary: str = ""

    def add(self, result: TestCaseResult) -> None:
        self.results.append(result)
        self.total += 1
        if result.status == "passed":
            self.passed += 1
        elif result.status == "failed":
            self.failed += 1
        elif result.status == "error":
            self.errors += 1
        elif result.status == "skipped":
            self.skipped += 1
        self.total_duration_ms += result.duration_ms

    def to_dict(self) -> dict:
        d = {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "pass_rate": round(self.passed / max(self.total, 1) * 100, 1),
            "summary": self.summary,
            "results": [asdict(r) for r in self.results],
        }
        return d


# ---------------------------------------------------------------------------
# Custom pytest plugin — collects results into TestSuiteReport
# ---------------------------------------------------------------------------

class _PytestCollectorPlugin:
    """Pytest plugin that populates a TestSuiteReport in real time."""

    def __init__(self, report: TestSuiteReport):
        self.report = report
        self._start_times: dict[str, float] = {}

    # -- hooks ---------------------------------------------------------------

    def pytest_runtest_logstart(self, nodeid: str, location: tuple) -> None:
        self._start_times[nodeid] = time.perf_counter()

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when != "call" and not (
            report.when == "setup" and report.skipped
        ):
            return

        nodeid = report.nodeid
        duration = (time.perf_counter() - self._start_times.get(nodeid, time.perf_counter())) * 1000

        category = "unit"
        lower = nodeid.lower()
        if "integration" in lower:
            category = "integration"
        elif "edge" in lower or "failure" in lower or "corrupt" in lower:
            category = "edge_case"

        status = "passed"
        tb = None
        if report.failed:
            status = "failed"
            tb = report.longreprtext
        elif report.skipped:
            status = "skipped"

        confidence = None
        if hasattr(report, "confidence_score"):
            confidence = report.confidence_score

        # Extract confidence from user_properties
        for key, val in getattr(report, "user_properties", []):
            if key == "confidence_score":
                confidence = val

        result = TestCaseResult(
            test_id=uuid.uuid4().hex[:8],
            test_name=nodeid.split("::")[-1],
            module=nodeid.split("::")[0],
            category=category,
            status=status,
            duration_ms=round(duration, 2),
            traceback_str=tb,
            confidence_score=confidence,
        )
        self.report.add(result)


# ---------------------------------------------------------------------------
# Custom unittest runner — collects results into TestSuiteReport
# ---------------------------------------------------------------------------

class _UnittestCollectorResult(unittest.TestResult):
    """unittest.TestResult subclass that populates a TestSuiteReport."""

    def __init__(self, report: TestSuiteReport, **kwargs: Any):
        super().__init__(**kwargs)
        self.report = report
        self._start: float = 0.0

    def startTest(self, test: unittest.TestCase) -> None:
        super().startTest(test)
        self._start = time.perf_counter()

    def _record(self, test: unittest.TestCase, status: str, tb: Optional[str] = None) -> None:
        duration = (time.perf_counter() - self._start) * 1000
        name = str(test)
        category = "unit"
        if "integration" in name.lower():
            category = "integration"
        elif "edge" in name.lower() or "failure" in name.lower():
            category = "edge_case"

        result = TestCaseResult(
            test_id=uuid.uuid4().hex[:8],
            test_name=name,
            module=test.__class__.__module__,
            category=category,
            status=status,
            duration_ms=round(duration, 2),
            traceback_str=tb,
        )
        self.report.add(result)

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._record(test, "passed")

    def addFailure(self, test: unittest.TestCase, err: tuple) -> None:
        super().addFailure(test, err)
        self._record(test, "failed", self._exc_info_to_string(err, test))

    def addError(self, test: unittest.TestCase, err: tuple) -> None:
        super().addError(test, err)
        self._record(test, "error", self._exc_info_to_string(err, test))

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._record(test, "skipped")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def run_pytest_suite(
    paths: list[str] | None = None,
    extra_args: list[str] | None = None,
    report_path: Path | str | None = None,
) -> TestSuiteReport:
    """Run pytest programmatically, return structured report, and save JSON."""
    report = TestSuiteReport()
    plugin = _PytestCollectorPlugin(report)

    args = list(paths or [str(Path(__file__).resolve().parent.parent / "tests")])
    args += extra_args or ["-v", "--tb=short", "-q"]

    pytest.main(args, plugins=[plugin])

    report.summary = (
        f"{report.passed}/{report.total} passed "
        f"({report.failed} failed, {report.errors} errors, {report.skipped} skipped) "
        f"in {report.total_duration_ms:.0f}ms"
    )

    _save_report(report, report_path)
    return report


def run_unittest_suite(
    suite: unittest.TestSuite | None = None,
    module_name: str | None = None,
    report_path: Path | str | None = None,
) -> TestSuiteReport:
    """Run unittest suite programmatically, return structured report, and save JSON."""
    report = TestSuiteReport()
    collector = _UnittestCollectorResult(report)

    if suite is None:
        loader = unittest.TestLoader()
        if module_name:
            suite = loader.loadTestsFromName(module_name)
        else:
            suite = loader.discover(
                str(Path(__file__).resolve().parent.parent / "tests"),
                pattern="test_*.py",
            )

    suite.run(collector)

    report.summary = (
        f"{report.passed}/{report.total} passed "
        f"({report.failed} failed, {report.errors} errors, {report.skipped} skipped) "
        f"in {report.total_duration_ms:.0f}ms"
    )

    _save_report(report, report_path)
    return report


def _save_report(report: TestSuiteReport, path: Path | str | None = None) -> Path:
    """Persist report as JSON."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if path is None:
        path = REPORTS_DIR / f"test_report_{report.run_id}.json"
    path = Path(path)
    path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
    return path


def load_latest_report(reports_dir: Path | str | None = None) -> dict | None:
    """Load the most recent JSON report from the reports directory."""
    d = Path(reports_dir) if reports_dir else REPORTS_DIR
    if not d.exists():
        return None
    files = sorted(d.glob("test_report_*.json"), key=os.path.getmtime, reverse=True)
    if not files:
        return None
    return json.loads(files[0].read_text())


def generate_audit_markdown_report(decision_data: dict) -> str:
    """
    Generate an enterprise-grade, audit-compliant QA Deployment Report.
    Adheres to ISO/IEC/IEEE 29119 reporting standards with zero decorative emojis.
    """
    total = decision_data.get("total", 0)
    passed = decision_data.get("passed", 0)
    failed = decision_data.get("failed", 0)
    errors = decision_data.get("errors", 0)
    skipped = decision_data.get("skipped", 0)
    pass_rate = decision_data.get("pass_rate", 0.0)
    duration_ms = decision_data.get("total_duration_ms", 0.0)
    approved = decision_data.get("approved", False)
    status_str = "APPROVED FOR PRODUCTION" if approved else "DEPLOYMENT BLOCKED"
    reviewer = decision_data.get("reviewer", "Unassigned")
    run_id = decision_data.get("run_id", "N/A")
    timestamp = decision_data.get("timestamp", datetime.now(timezone.utc).isoformat())
    signature = decision_data.get("signature", "UNVERIFIED")
    target_artifact = decision_data.get("target_artifact", "Backend Services & RAG Pipeline")

    market_score = decision_data.get("market_readiness_score")
    pillar_scores = decision_data.get("pillar_scores")
    archetype = decision_data.get("archetype", "Generic Software System")

    lines = [
        "# SOFTWARE QUALITY ASSURANCE & MARKET READINESS AUDIT REPORT",
        "",
        "## 1. Executive Summary",
        "",
        "| Audit Field | Record Specification |",
        "|:---|:---|",
        f"| Audit Execution Identifier | `{run_id}` |",
        f"| Evaluation Timestamp (UTC) | `{timestamp}` |",
        f"| Quality Assurance Authority | `{reviewer}` |",
        f"| System Archetype | `{archetype}` |",
        f"| Quality Gate Determination | **{status_str}** |",
        f"| Market Readiness Index | **{market_score if market_score is not None else pass_rate:.1f} / 100.0** |",
        f"| Target Evaluation Artifact | `{target_artifact}` |",
        f"| Cryptographic Digest (SHA-256) | `{signature}` |",
        "",
        "### Governance Determination Statement",
        "",
    ]

    if approved:
        lines.append(
            "The target artifact has successfully satisfied the quality threshold criteria. "
            "All executed test cases, assertions, boundary conditions, and security static heuristics have either "
            "passed verification or were systematically reviewed, justified, and certified under formal Quality Assurance governance."
        )
    else:
        lines.append(
            "The target artifact failed to satisfy pre-deployment quality and security requirements. "
            "One or more functional failures, unhandled exceptions, or unreviewed critical security vulnerabilities were identified. "
            "Deployment to production environments is prohibited until remediation is verified."
        )

    # 5-Pillar Scorecard
    if pillar_scores:
        lines += [
            "",
            "## 2. Multi-Pillar Market Readiness Scorecard",
            "",
            "| Evaluation Pillar | Score (0 - 100) | Weight | Compliance Determination |",
            "|:---|:---:|:---:|:---|",
            f"| Application Security (SAST / Secrets / CVE) | {pillar_scores.get('security_score', 100.0):.1f} | 30% | {'Compliant' if pillar_scores.get('security_score', 100.0) >= 85 else 'Vulnerable'} |",
            f"| Functional Reliability & Test Verification | {pillar_scores.get('reliability_score', 100.0):.1f} | 25% | {'Verified' if pillar_scores.get('reliability_score', 100.0) >= 90 else 'Degraded'} |",
            f"| Code Health & Maintainability Index | {pillar_scores.get('code_health_score', 100.0):.1f} | 20% | {'Maintainable' if pillar_scores.get('code_health_score', 100.0) >= 70 else 'Technical Debt'} |",
            f"| API Contract & Interface Conformance | {pillar_scores.get('api_readiness_score', 100.0):.1f} | 15% | {'Certified' if pillar_scores.get('api_readiness_score', 100.0) >= 80 else 'Contract Defect'} |",
            f"| GenAI & RAG Safety / Injection Resilience | {pillar_scores.get('genai_safety_score', 100.0):.1f} | 10% | {'Resilient' if pillar_scores.get('genai_safety_score', 100.0) >= 80 else 'Review Advised'} |",
            f"| **Aggregated Market Readiness Score** | **{market_score if market_score is not None else 100.0:.1f}** | **100%** | **{status_str}** |",
            "",
        ]

    # Security Findings Register
    sec_summary = decision_data.get("security_summary")
    if sec_summary and sec_summary.get("findings"):
        lines += [
            "## 3. Application Security & Vulnerability Register (OWASP Top 10)",
            "",
            "| Finding ID | CWE | Severity | Category | Target Location | Remediation Specification |",
            "|:---|:---|:---:|:---|:---|:---|",
        ]
        for f in sec_summary["findings"]:
            fid = f.get("finding_id", "VULN-0000")
            cwe = f.get("cwe_id", "CWE-Unknown")
            sev = f.get("severity", "MEDIUM").upper()
            title = f.get("title", "").replace("|", "\\|")
            loc = f"{Path(f.get('file_path', '')).name}:{f.get('line_number', 0)}"
            rem = f.get("remediation_guidance", "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{fid}` | `{cwe}` | [{sev}] | {title} | `{loc}` | {rem} |")
        lines.append("")

    lines += [
        "",
        "## 4. Test Execution Metrics and Benchmarks",
        "",
        "| Metric Classification | Absolute Count | Proportional Ratio | Compliance Status |",
        "|:---|:---:|:---:|:---|",
        f"| Total Test Cases Executed | {total} | 100.0% | Complete |",
        f"| Verification Success (Passed) | {passed} | {pass_rate:.1f}% | {'Compliant' if failed == 0 and errors == 0 else 'Sub-optimal'} |",
        f"| Functional Defect Failures | {failed} | {(failed / max(total, 1) * 100):.1f}% | {'Zero Defects' if failed == 0 else 'Action Required'} |",
        f"| Execution Faults / Errors | {errors} | {(errors / max(total, 1) * 100):.1f}% | {'Zero Errors' if errors == 0 else 'Action Required'} |",
        f"| Excluded / Skipped Cases | {skipped} | {(skipped / max(total, 1) * 100):.1f}% | Permissible |",
        f"| Total Execution Latency | {duration_ms:.2f} ms | SLA Threshold: <10,000 ms | {'Within SLA' if duration_ms < 10000 else 'Exceeds SLA'} |",
        "",
    ]

    spec_review = decision_data.get("specialist_review")
    if spec_review:
        lines += [
            "## 5. Local Fine-Tuned AI Specialist Deep-Dive Audit",
            "",
            f"- **Autonomous Specialist Model:** `{spec_review.get('model_identifier', 'qa-auditor-specialist')}`",
            f"- **Secondary Gate Verdict:** `[{spec_review.get('gate_recommendation', 'VERIFIED')}]`",
            f"- **Model Evaluation Confidence:** `{spec_review.get('confidence_score', 0.95) * 100:.1f}%`",
            f"- **Cryptographic Review Digest:** `{spec_review.get('cryptographic_digest', 'N/A')}`",
            "",
            f"**Specialist Executive Synthesis:**",
            f"> {spec_review.get('executive_summary', '')}",
            "",
        ]
        t_findings = spec_review.get("threat_findings", [])
        if t_findings:
            lines += [
                "### Confirmed Exploitability & Threat Modeling",
                "",
                "| Finding ID | CWE | CVSS | Exploitability | Attack Vector & Rationale | Remediation |",
                "|:---|:---|:---:|:---|:---|:---|",
            ]
            for tf in t_findings:
                lines.append(
                    f"| `{tf.get('finding_id', '-')}` | `{tf.get('cwe_id', '-')}` | "
                    f"{tf.get('cvss_v3_score', 0.0):.1f} | [{tf.get('exploitability', 'THEORETICAL')}] | "
                    f"{tf.get('attack_vector', '')}: {tf.get('auditor_rationale', '')} | "
                    f"`{tf.get('remediation_patch', '')[:60]}` |"
                )
            lines.append("")

        d_diags = spec_review.get("defect_diagnoses", [])
        if d_diags:
            lines += [
                "### Defect Diagnoses & Suggested Code Diffs",
                "",
                "| Test Identifier | Failure Type | Root Cause Scope | Remediation Guidance |",
                "|:---|:---|:---|:---|",
            ]
            for dd in d_diags:
                lines.append(
                    f"| `{dd.get('test_id', '-')}` | {dd.get('failure_type', '-')} | "
                    f"{dd.get('root_cause', '')} | {dd.get('suggested_fix', '')} |"
                )
            lines.append("")

    failure_analyses = decision_data.get("failure_analyses", [])
    if failure_analyses:
        lines += [
            "## 6. Defect Analysis and Root Cause Remediation" if spec_review else "## 5. Defect Analysis and Root Cause Remediation",
            "",
            "| Defect Scope | Severity Classification | Defect Category | Root Cause Assessment | Remediation Recommendation |",
            "|:---|:---|:---|:---|:---|",
        ]
        for fa in failure_analyses:
            name = fa.get("test_name", "Unknown").replace("|", "\\|")
            sev = fa.get("severity", "MEDIUM").upper()
            cat = fa.get("category", "General").replace("|", "\\|")
            cause = fa.get("root_cause", "No analysis available.").replace("\n", " ").replace("|", "\\|")
            fix = fa.get("suggested_fix", "Review traceback manually.").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{name}` | [{sev}] | {cat} | {cause} | {fix} |")
        lines.append("")

    overrides = decision_data.get("overrides", {})
    qa_notes = decision_data.get("qa_notes", {})
    if overrides or qa_notes:
        lines += [
            "## 6. Human-In-The-Loop Overrides and Reviewer Annotations",
            "",
        ]
        if overrides:
            for test_name, status in overrides.items():
                note = qa_notes.get(test_name, "No specific reviewer comment logged.")
                lines.append(f"- **Target Assertion:** `{test_name}`")
                lines.append(f"  - **Quality Gate Waiver Status:** {status}")
                lines.append(f"  - **Reviewer Justification:** {note}")
                lines.append("")
        else:
            lines.append("No active waivers. Verification conducted without quality gate overrides.")
            lines.append("")

        general_notes = {k: v for k, v in qa_notes.items() if k not in overrides}
        if general_notes:
            lines.append("### General Reviewer Notes")
            for key, val in general_notes.items():
                lines.append(f"- **{key}:** {val}")
            lines.append("")

    # Detailed test results register
    results = decision_data.get("results", [])
    if results:
        lines += [
            "## 7. Detailed Test Execution Register",
            "",
            "| Test Case Identifier | Module Path | Category | Latency (ms) | Verification Outcome |",
            "|:---|:---|:---|:---:|:---|",
        ]
        for r in results:
            name = r.get("test_name", "unknown")
            module = r.get("module", "-")
            cat = r.get("category", "unit")
            dur = r.get("duration_ms", 0.0)
            status = r.get("status", "unknown").upper()
            lines.append(f"| `{name}` | `{module}` | {cat} | {dur:.1f} | [{status}] |")
        lines.append("")

    lines += [
        "## 8. Regulatory Certification and Verification Sign-Off",
        "",
        "This report certifies that the above testing procedure was conducted programmatically using automated verification harnesses and evaluated by authorized personnel.",
        "",
        "```",
        f"Sign-off Authority: {reviewer}",
        f"Verification Timestamp: {timestamp}",
        f"Cryptographic Integrity Signature: {signature}",
        "Audit Standard: ISO/IEC/IEEE 29119 Software Quality Verification",
        "```",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    report = run_pytest_suite()
    print(json.dumps(report.to_dict(), indent=2))
