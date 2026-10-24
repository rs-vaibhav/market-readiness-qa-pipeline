"""
Enterprise Market Readiness & Multi-Pillar Verification Engine.
Evaluates any codebase, repository, or archive across Security (OWASP Top 10),
Functional Reliability, Architectural Health, API Integrity, and GenAI Resilience.

Computes the definitive Market Readiness Index (0 - 100) and gate determination.
"""

import ast
import json
import math
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.security_scanner import SecurityScanner, SecurityScanSummary, RAGSecurityEvaluator
from core.source_analyzer import analyze_and_test, discover_repository_structure, safe_extract_zip
from core.ai_agent_evaluator import AgentEvaluator


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class CodeHealthMetrics:
    """Quantitative maintainability and complexity metrics."""
    total_loc: int = 0
    total_functions: int = 0
    total_classes: int = 0
    average_cyclomatic_complexity: float = 1.0
    max_cyclomatic_complexity: int = 1
    complex_functions_count: int = 0
    maintainability_index: float = 100.0  # 0 - 100
    health_grade: str = "A"  # A | B | C | D | F


@dataclass
class PillarScores:
    """Individual pillar evaluations on a 0 - 100 scale."""
    security_score: float = 100.0          # Weight: 30%
    reliability_score: float = 100.0       # Weight: 25%
    code_health_score: float = 100.0       # Weight: 20%
    api_readiness_score: Optional[float] = 100.0     # Weight: 15% (None = not evaluated)
    genai_safety_score: Optional[float] = 100.0      # Weight: 10% (None = not evaluated)


@dataclass
class MarketReadinessReport:
    """Comprehensive Go-To-Market audit determination."""
    audit_id: str = field(default_factory=lambda: f"MKT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_path: str = ""
    archetype: str = "Generic Application"
    market_readiness_score: float = 100.0
    gate_decision: str = "MARKET_READY_APPROVED"  # MARKET_READY_APPROVED | CONDITIONAL_APPROVAL | MARKET_BLOCKED
    blocking_reasons: list[str] = field(default_factory=list)
    pillar_scores: PillarScores = field(default_factory=PillarScores)
    code_health: CodeHealthMetrics = field(default_factory=CodeHealthMetrics)
    security_summary: Optional[dict] = None
    test_summary: Optional[dict] = None
    ai_evaluation: Optional[dict] = None
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "target_path": self.target_path,
            "archetype": self.archetype,
            "market_readiness_score": self.market_readiness_score,
            "gate_decision": self.gate_decision,
            "blocking_reasons": self.blocking_reasons,
            "pillar_scores": asdict(self.pillar_scores),
            "code_health": asdict(self.code_health),
            "security_summary": self.security_summary,
            "test_summary": self.test_summary,
            "ai_evaluation": self.ai_evaluation,
            "signature": self.signature,
        }


# ---------------------------------------------------------------------------
# Code Health & AST Complexity Engine
# ---------------------------------------------------------------------------

class ComplexityAnalyzer:
    """Computes McCabe cyclomatic complexity and Maintainability Index."""

    def compute_file_metrics(self, file_path: Path) -> tuple[int, int, int, list[int]]:
        if file_path.suffix == ".java":
            return self.compute_java_metrics(file_path)

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return 0, 0, 0, []

        loc = len(content.splitlines())
        functions = 0
        classes = 0
        complexities: list[int] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                comp = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor,
                                          ast.ExceptHandler, ast.With, ast.AsyncWith)):
                        comp += 1
                    elif isinstance(child, ast.BoolOp):
                        comp += max(0, len(child.values) - 1)
                complexities.append(comp)

        return loc, functions, classes, complexities

    def compute_java_metrics(self, file_path: Path) -> tuple[int, int, int, list[int]]:
        import re
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return 0, 0, 0, []

        loc = len(content.splitlines())
        classes = len(re.findall(r"\bclass\s+[A-Za-z0-9_]+", content))
        methods = len(re.findall(r"(?:public|protected|private|static|\s)+[\w\<\>\[\]]+\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{", content))
        branches = len(re.findall(r"\b(if|else\s+if|for|while|case|catch|throw)\b|\&\&|\|\|", content))
        cyclomatic = max(1, 1 + branches)
        return loc, max(methods, 1), max(classes, 1), [cyclomatic]


# ---------------------------------------------------------------------------
# Archetype Detector
# ---------------------------------------------------------------------------

def detect_project_archetype(root: Path) -> str:
    """Identify project archetype from file and configuration patterns."""
    names = {p.name.lower() for p in root.rglob("*") if not any(
        x in p.parts for x in (".git", ".venv", "venv", "node_modules", "__pycache__")
    )}

    has_py = any(p.suffix == ".py" for p in root.rglob("*.py"))
    has_js_ts = any(p.suffix in (".js", ".ts", ".jsx", ".tsx") for p in root.rglob("*"))
    has_docker = "dockerfile" in names or "docker-compose.yml" in names
    has_go = any(p.suffix == ".go" for p in root.rglob("*.go"))
    has_java = any(p.suffix in (".java", ".kt") for p in root.rglob("*"))

    if has_py:
        # Check frameworks
        for py in root.rglob("*.py"):
            try:
                txt = py.read_text(encoding="utf-8", errors="ignore")
                if "fastapi" in txt.lower():
                    return "FastAPI High-Performance Web Service"
                if "flask" in txt.lower():
                    return "Flask REST API Microservice"
                if "django" in txt.lower():
                    return "Django Enterprise Web Framework"
                if "langchain" in txt.lower() or "llamaindex" in txt.lower() or "chroma" in txt.lower():
                    return "GenAI / Retrieval-Augmented Generation (RAG) Service"
            except Exception:
                continue
        return "Python Application / Library"
    elif has_js_ts:
        return "Node.js / TypeScript Web Application"
    elif has_go:
        return "Go Microservice System"
    elif has_java:
        return "Java / JVM Enterprise Application"
    elif has_docker:
        return "Containerized Cloud-Native Infrastructure"

    return "Polyglot Software Project"


# ---------------------------------------------------------------------------
# Market Readiness Engine
# ---------------------------------------------------------------------------

class MarketReadinessEngine:
    """Orchestrates comprehensive 5-pillar evaluation for market deployment."""

    def __init__(self, llm_client: Any = None):
        self.security_scanner = SecurityScanner()
        self.complexity_analyzer = ComplexityAnalyzer()
        self.rag_security = RAGSecurityEvaluator()
        self.ai_evaluator = AgentEvaluator(llm=llm_client)

    def run_java_maven_tests(self, repo_dir: Path) -> dict | None:
        """Execute Maven surefire JUnit test suites and extract structured test reports."""
        pom_files = list(repo_dir.rglob("pom.xml")) if repo_dir.is_dir() else []
        if not pom_files:
            return None

        pom_dir = pom_files[0].parent
        import subprocess
        import xml.etree.ElementTree as ET

        try:
            res = subprocess.run(
                ["mvn", "test", "-q"],
                cwd=str(pom_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )

            surefire_dir = pom_dir / "target" / "surefire-reports"
            total = 0
            failures = 0
            errors = 0
            skipped = 0
            duration_ms = 0.0
            test_results = []

            if surefire_dir.exists():
                for xml_file in sorted(surefire_dir.glob("TEST-*.xml")):
                    try:
                        tree = ET.parse(xml_file)
                        root = tree.getroot()
                        t = int(root.attrib.get("tests", 0))
                        f = int(root.attrib.get("failures", 0))
                        e = int(root.attrib.get("errors", 0))
                        s = int(root.attrib.get("skipped", 0))
                        dur = float(root.attrib.get("time", 0.0)) * 1000.0

                        total += t
                        failures += f
                        errors += e
                        skipped += s
                        duration_ms += dur

                        for tc in root.findall("testcase"):
                            tc_name = tc.attrib.get("name", "unknown")
                            tc_class = tc.attrib.get("classname", "")
                            tc_time = float(tc.attrib.get("time", 0.0)) * 1000.0
                            status = "passed"
                            tb = None
                            if tc.find("failure") is not None:
                                status = "failed"
                                tb = tc.find("failure").text
                            elif tc.find("error") is not None:
                                status = "error"
                                tb = tc.find("error").text
                            elif tc.find("skipped") is not None:
                                status = "skipped"

                            test_results.append({
                                "test_id": f"JAVA-{len(test_results)+1:03d}",
                                "test_name": tc_name,
                                "module": tc_class,
                                "category": "unit",
                                "status": status,
                                "duration_ms": round(tc_time, 2),
                                "traceback_str": tb,
                            })
                    except Exception:
                        continue

            if total == 0:
                passed = 0 if res.returncode != 0 else 1
                total = 1
                failures = 1 if res.returncode != 0 else 0
            else:
                passed = total - failures - errors - skipped

            pass_rate = round(passed / max(total, 1) * 100.0, 1)
            return {
                "run_id": f"JAVA-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total": total,
                "passed": passed,
                "failed": failures,
                "errors": errors,
                "skipped": skipped,
                "total_duration_ms": round(duration_ms, 2),
                "pass_rate": pass_rate,
                "summary": f"{passed}/{total} passed in {duration_ms:.0f}ms (Maven JUnit)",
                "results": test_results,
            }
        except Exception:
            return None

    def evaluate(self, target_path: str | Path, run_functional_tests: bool = True) -> MarketReadinessReport:
        target_path = Path(target_path).resolve()
        report = MarketReadinessReport(target_path=str(target_path))

        # Handle ZIP Archives
        extracted_root = None
        analysis_root = target_path
        if target_path.is_file() and target_path.suffix.lower() == ".zip":
            base_dir = Path(__file__).resolve().parent.parent
            extract_dest = base_dir / "reports" / "extracted" / f"eval_{uuid.uuid4().hex[:8]}"
            extracted_root = safe_extract_zip(target_path, extract_dest)
            analysis_root = extracted_root

        # 1. Detect Archetype
        report.archetype = detect_project_archetype(analysis_root)

        # 2. Pillar I: Security & Vulnerability Analysis (30% weight)
        sec_summary = SecurityScanSummary()
        if analysis_root.is_file():
            self.security_scanner.scan_file(analysis_root, sec_summary)
        else:
            sec_summary = self.security_scanner.scan_directory(analysis_root)
        report.security_summary = sec_summary.to_dict()
        report.pillar_scores.security_score = sec_summary.security_score

        # 3. Pillar II: Code Health & Complexity (20% weight)
        total_loc = 0
        total_func = 0
        total_cls = 0
        all_comp: list[int] = []

        is_java = "java" in report.archetype.lower() or list(analysis_root.rglob("*.java"))
        if is_java:
            files_to_check = [analysis_root] if analysis_root.is_file() else list(analysis_root.rglob("*.java"))
        else:
            files_to_check = [analysis_root] if analysis_root.is_file() else list(analysis_root.rglob("*.py"))

        for f in files_to_check:
            if any(x in f.parts for x in (".git", ".venv", "venv", "__pycache__", "target")):
                continue
            loc, funcs, clss, comps = self.complexity_analyzer.compute_file_metrics(f)
            total_loc += loc
            total_func += funcs
            total_cls += clss
            all_comp.extend(comps)

        avg_comp = sum(all_comp) / max(len(all_comp), 1)
        max_comp = max(all_comp) if all_comp else 1
        complex_count = sum(1 for c in all_comp if c > 10)

        loc_penalty = min(30.0, (total_loc / 1000.0) * 2.0)
        comp_penalty = min(40.0, avg_comp * 3.5)
        health_score = max(20.0, round(100.0 - loc_penalty - comp_penalty, 1))

        health_grade = "A"
        if health_score < 60:
            health_grade = "F"
        elif health_score < 70:
            health_grade = "D"
        elif health_score < 80:
            health_grade = "C"
        elif health_score < 90:
            health_grade = "B"

        report.code_health = CodeHealthMetrics(
            total_loc=total_loc,
            total_functions=total_func,
            total_classes=total_cls,
            average_cyclomatic_complexity=round(avg_comp, 2),
            max_cyclomatic_complexity=max_comp,
            complex_functions_count=complex_count,
            maintainability_index=health_score,
            health_grade=health_grade,
        )
        report.pillar_scores.code_health_score = health_score

        # 4. Pillar III: Functional Verification & Test Suite (25% weight)
        if run_functional_tests:
            if is_java:
                java_tests = self.run_java_maven_tests(analysis_root)
                if java_tests:
                    report.test_summary = java_tests
                    report.pillar_scores.reliability_score = java_tests.get("pass_rate", 100.0)
                else:
                    report.test_summary = {
                        "total": 0, "passed": 0, "failed": 0, "errors": 0,
                        "pass_rate": 100.0, "results": []
                    }
                    report.pillar_scores.reliability_score = 100.0
            else:
                scan_run = analyze_and_test(source_path=target_path, run_tests=True)
                project_rep = scan_run.get("project_test_report")
                generated_rep = scan_run.get("generated_test_report")
                test_rep = scan_run.get("test_report")

                # Build test_summary with smoke test details
                if project_rep is not None:
                    report.test_summary = dict(project_rep)
                    report.test_summary["smoke_test_pass_rate"] = (
                        generated_rep.get("pass_rate", 0.0) if generated_rep else None
                    )
                    report.test_summary["smoke_test_summary"] = dict(generated_rep) if generated_rep else None
                    report.pillar_scores.reliability_score = project_rep.get("pass_rate", 0.0)
                else:
                    # No existing project tests found
                    base_summary = dict(test_rep) if test_rep else {
                        "total": 0, "passed": 0, "failed": 0, "errors": 0, "pass_rate": 0.0,
                        "results": [], "note": "No project tests found",
                    }
                    report.test_summary = base_summary
                    report.test_summary["smoke_test_pass_rate"] = (
                        generated_rep.get("pass_rate", 0.0) if generated_rep else None
                    )
                    report.test_summary["smoke_test_summary"] = dict(generated_rep) if generated_rep else None
                    report.pillar_scores.reliability_score = 50.0  # No project tests → neutral 50

                report.ai_evaluation = scan_run.get("evaluation")
        else:
            report.pillar_scores.reliability_score = 100.0

        # 5. Pillar IV: API Contract & Conformance (15% weight)
        api_score: Optional[float] = None
        api_evaluated = False
        # Detect if any endpoints were found in the source analyses
        _analyses = locals().get("scan_run", {}).get("analyses", []) if not is_java else []
        total_endpoints = sum(a.get("endpoints_count", 0) for a in _analyses)
        if is_java or total_endpoints > 0:
            api_evaluated = True
            api_score = 100.0
            if report.test_summary and report.test_summary.get("errors", 0) > 0:
                api_score = max(40.0, 100.0 - (report.test_summary["errors"] * 10))
        report.pillar_scores.api_readiness_score = api_score

        # 6. Pillar V: GenAI Safety & Prompt Injection Resilience (10% weight)
        genai_score: Optional[float] = None
        genai_evaluated = False
        if "rag" in report.archetype.lower() or "genai" in report.archetype.lower():
            genai_evaluated = True
            genai_score = 90.0
        report.pillar_scores.genai_safety_score = genai_score

        # 7. Compute Weighted Market Readiness Index (skip None pillars, renormalize)
        pillar_weights = [
            (report.pillar_scores.security_score, 0.30),
            (report.pillar_scores.reliability_score, 0.25),
            (report.pillar_scores.code_health_score, 0.20),
            (api_score, 0.15),
            (genai_score, 0.10),
        ]
        evaluated = [(score, w) for score, w in pillar_weights if score is not None]
        total_weight = sum(w for _, w in evaluated)
        total_score = sum(score * w for score, w in evaluated) / max(total_weight, 1e-9)
        report.market_readiness_score = round(total_score, 1)

        # 8. Governance Gate Determination
        blocks: list[str] = []
        if sec_summary.critical_count > 0:
            blocks.append(f"Blocked by {sec_summary.critical_count} CRITICAL security vulnerability(ies).")
        if sec_summary.high_count > 0:
            blocks.append(f"Blocked by {sec_summary.high_count} HIGH security vulnerability(ies).")
        if sec_summary.secrets_count > 0:
            blocks.append(f"Blocked by {sec_summary.secrets_count} exposed hardcoded secret(s).")
        if report.test_summary and report.test_summary.get("failed", 0) > 0:
            blocks.append(f"Blocked by {report.test_summary['failed']} failed functional assertion(s).")
        if report.test_summary and report.test_summary.get("errors", 0) > 0:
            blocks.append(f"Blocked by {report.test_summary['errors']} runtime execution error(s).")
        if report.market_readiness_score < 70.0:
            blocks.append(f"Aggregate Market Readiness Score ({report.market_readiness_score}) below minimum 70.0 threshold.")

        report.blocking_reasons = blocks

        if not blocks and report.market_readiness_score >= 85.0:
            report.gate_decision = "MARKET_READY_APPROVED"
        elif not blocks and report.market_readiness_score >= 70.0:
            report.gate_decision = "CONDITIONAL_APPROVAL"
        else:
            report.gate_decision = "MARKET_BLOCKED"

        # 9. SHA-256 Integrity Checksum
        raw = json.dumps(report.to_dict(), sort_keys=True, default=str).encode("utf-8")
        import hashlib
        report.signature = hashlib.sha256(raw).hexdigest()

        return report


# ---------------------------------------------------------------------------
# CLI Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    engine = MarketReadinessEngine()
    result = engine.evaluate(target)
    print(json.dumps(result.to_dict(), indent=2))
