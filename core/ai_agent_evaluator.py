"""
AI Agent Evaluator — uses local open-source models (Ollama: llama3.2, qwen2.5-coder,
deepseek-r1, llama3.3, or vLLM/OpenAI-compatible local endpoints) to perform
deep security audit reasoning, defect root-cause analysis, and RAG verification.
"""

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Protocol

import httpx


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class FailureAnalysis:
    """AI-generated analysis for a single failed test."""
    test_name: str
    root_cause: str
    suggested_fix: str
    severity: str  # critical | high | medium | low
    category: str  # logic_error | config | data | timeout | hallucination | abstention


@dataclass
class SecurityAuditAnalysis:
    """AI-driven security vulnerability validation and exploitability assessment."""
    finding_id: str
    rule_id: str
    cvss_score: float
    is_exploitable: bool
    attack_vector: str
    exact_remediation_diff: str
    audit_notes: str


@dataclass
class RAGEvaluation:
    """Faithfulness & abstention evaluation of a RAG response."""
    query: str
    generated_answer: str
    ground_truth: str
    faithfulness_score: float  # 0.0 – 1.0
    abstention_correct: bool
    reasoning: str


@dataclass
class EvaluationReport:
    """Complete AI evaluation output."""
    model_used: str = "mock"
    ai_available: bool = True
    failure_analyses: list[FailureAnalysis] = field(default_factory=list)
    security_audits: list[SecurityAuditAnalysis] = field(default_factory=list)
    rag_evaluations: list[RAGEvaluation] = field(default_factory=list)
    overall_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "model_used": self.model_used,
            "ai_available": self.ai_available,
            "failure_analyses": [asdict(a) for a in self.failure_analyses],
            "security_audits": [asdict(s) for s in self.security_audits],
            "rag_evaluations": [asdict(e) for e in self.rag_evaluations],
            "overall_summary": self.overall_summary,
        }


# ---------------------------------------------------------------------------
# Local Open-Source Model Discovery & Interfaces
# ---------------------------------------------------------------------------

def get_available_ollama_models(base_url: str = "http://localhost:11434") -> list[str]:
    """Retrieve list of locally installed open-source models in Ollama."""
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=3.0)
        if resp.status_code == 200:
            models = [m.get("name") for m in resp.json().get("models", []) if m.get("name")]
            return models
    except Exception:
        pass
    return []


class LLMClient(Protocol):
    def generate(self, prompt: str, system: str = "") -> str: ...
    @property
    def model_name(self) -> str: ...


class OllamaClient:
    """Calls a local Ollama instance (llama3.2, qwen2.5-coder, deepseek-r1, etc.)."""

    IS_MOCK = False

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @property
    def model_name(self) -> str:
        return f"ollama/{self.model}"

    def generate(self, prompt: str, system: str = "") -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 8192},
        }
        if system:
            payload["system"] = system

        try:
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except httpx.HTTPError as exc:
            return f"[Ollama API connection error: {exc}]"


class MockLLMClient:
    """Deterministic mock client for offline verification."""

    IS_MOCK = True

    @property
    def model_name(self) -> str:
        return "deterministic-mock-engine"

    def generate(self, prompt: str, system: str = "") -> str:
        lower = prompt.lower()

        if "security" in lower or "vulnerability" in lower:
            return json.dumps({
                "cvss_score": 8.5,
                "is_exploitable": True,
                "attack_vector": "Remote unauthorized input injection via unvalidated parameters.",
                "exact_remediation_diff": "- subprocess.Popen(cmd, shell=True)\n+ subprocess.Popen(shlex.split(cmd), shell=False)",
                "audit_notes": "Identified critical command execution path. Immediate refactoring required.",
            })

        if "root cause" in lower or "failed test" in lower:
            return json.dumps({
                "root_cause": "Assertion failure: Return payload schema missing mandatory attributes.",
                "suggested_fix": (
                    "Ensure response serialization incorporates required field definitions. "
                    "Validate return payload schema against strict contract."
                ),
                "severity": "high",
                "category": "logic_error",
            })

        if "faithfulness" in lower or "ground truth" in lower:
            return json.dumps({
                "faithfulness_score": 0.92,
                "abstention_correct": True,
                "reasoning": (
                    "The generated answer correctly reflects key factual assertions from ground truth references."
                ),
            })

        return '{"message": "Verification evaluation complete."}'


# ---------------------------------------------------------------------------
# Evaluator Engine
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a Principal Software Quality Assurance & Application Security Architect. "
    "Respond ONLY with valid JSON. Do not include markdown code fences, conversational prose, or emojis."
)


def _parse_json_response(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {"raw": raw, "parse_error": True}


class AgentEvaluator:
    """Orchestrates AI-driven defect root cause and security vulnerability auditing."""

    def __init__(self, llm: LLMClient | None = None, model_name: str | None = None):
        if llm:
            self.llm = llm
        else:
            self.llm = self._resolve_client(model_name)

    @staticmethod
    def _resolve_client(model_name: str | None = None) -> LLMClient:
        try:
            available = get_available_ollama_models()
            if available:
                selected_model = model_name if model_name in available else available[0]
                return OllamaClient(model=selected_model)
        except Exception:
            pass
        return MockLLMClient()

    def analyze_failure(self, test_name: str, traceback_str: str, context: str = "") -> FailureAnalysis:
        if getattr(self.llm, "IS_MOCK", False):
            return FailureAnalysis(
                test_name=test_name,
                root_cause="AI review unavailable — Ollama offline.",
                suggested_fix="Start Ollama and re-run for AI-assisted diagnosis.",
                severity="medium",
                category="logic_error",
            )

        prompt = (
            f"Test `{test_name}` encountered a failure with the following traceback record:\n\n"
            f"```\n{traceback_str}\n```\n\n"
        )
        if context:
            prompt += f"Execution Context:\n{context}\n\n"
        prompt += (
            "Return a JSON object with keys: root_cause (string), suggested_fix (string), "
            "severity (critical|high|medium|low), category (logic_error|config|data|timeout|hallucination|abstention)."
        )

        raw = self.llm.generate(prompt, system=_SYSTEM_PROMPT)
        data = _parse_json_response(raw)

        return FailureAnalysis(
            test_name=test_name,
            root_cause=data.get("root_cause", raw[:300]),
            suggested_fix=data.get("suggested_fix", "Review traceback manually."),
            severity=data.get("severity", "medium"),
            category=data.get("category", "logic_error"),
        )

    def audit_security_vulnerability(self, finding_dict: dict, code_context: str = "") -> SecurityAuditAnalysis:
        """Deep security reasoning on an identified vulnerability finding."""
        if getattr(self.llm, "IS_MOCK", False):
            return SecurityAuditAnalysis(
                finding_id=finding_dict.get("finding_id", "VULN-0000"),
                rule_id=finding_dict.get("rule_id", "SAST-000"),
                cvss_score=0.0,
                is_exploitable=False,
                attack_vector="Static heuristic detection only.",
                exact_remediation_diff="AI review unavailable — start Ollama to enable automated patch generation.",
                audit_notes="AI review unavailable — Ollama offline. Static heuristic detection only.",
            )

        prompt = (
            f"Audit the following security finding in the codebase:\n\n"
            f"Finding ID: {finding_dict.get('finding_id')}\n"
            f"Rule ID: {finding_dict.get('rule_id')}\n"
            f"CWE: {finding_dict.get('cwe_id')}\n"
            f"Title: {finding_dict.get('title')}\n"
            f"Snippet: {finding_dict.get('code_snippet')}\n"
            f"File: {finding_dict.get('file_path')}:{finding_dict.get('line_number')}\n\n"
        )
        if code_context:
            prompt += f"Surrounding Code Context:\n```\n{code_context}\n```\n\n"

        prompt += (
            "Determine exploitability and construct a precise remediation diff. "
            "Return JSON with keys: cvss_score (float 0-10), is_exploitable (bool), "
            "attack_vector (string), exact_remediation_diff (unified diff string), audit_notes (string)."
        )

        raw = self.llm.generate(prompt, system=_SYSTEM_PROMPT)
        data = _parse_json_response(raw)

        return SecurityAuditAnalysis(
            finding_id=finding_dict.get("finding_id", "VULN-0000"),
            rule_id=finding_dict.get("rule_id", "SAST-000"),
            cvss_score=float(data.get("cvss_score", 7.0)),
            is_exploitable=bool(data.get("is_exploitable", True)),
            attack_vector=data.get("attack_vector", "Untrusted parameter ingestion."),
            exact_remediation_diff=data.get("exact_remediation_diff", "Apply input validation."),
            audit_notes=data.get("audit_notes", "Vulnerability confirmed via static heuristic analysis."),
        )

    def evaluate_rag(
        self,
        query: str,
        generated_answer: str,
        ground_truth: str,
        is_abstention_expected: bool = False,
    ) -> RAGEvaluation:
        if getattr(self.llm, "IS_MOCK", False):
            return RAGEvaluation(
                query=query,
                generated_answer=generated_answer,
                ground_truth=ground_truth,
                faithfulness_score=0.0,
                abstention_correct=False,
                reasoning="AI review unavailable — Ollama offline. Cannot evaluate RAG faithfulness without an active model.",
            )

        prompt = (
            "Evaluate the following RAG output for faithfulness.\n\n"
            f"Query: {query}\n"
            f"Generated Answer: {generated_answer}\n"
            f"Ground Truth: {ground_truth}\n"
            f"Abstention Expected: {is_abstention_expected}\n\n"
            "Return JSON with keys: faithfulness_score (float 0-1), "
            "abstention_correct (bool), reasoning (string)."
        )

        raw = self.llm.generate(prompt, system=_SYSTEM_PROMPT)
        data = _parse_json_response(raw)

        score = data.get("faithfulness_score", 0.0)
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = 0.0

        return RAGEvaluation(
            query=query,
            generated_answer=generated_answer,
            ground_truth=ground_truth,
            faithfulness_score=min(max(float(score), 0.0), 1.0),
            abstention_correct=bool(data.get("abstention_correct", False)),
            reasoning=data.get("reasoning", raw[:300]),
        )

    def analyze_test_report(self, report_dict: dict) -> EvaluationReport:
        is_mock = getattr(self.llm, "IS_MOCK", False)
        eval_report = EvaluationReport(
            model_used=self.llm.model_name,
            ai_available=not is_mock,
        )

        failed = [
            r for r in report_dict.get("results", [])
            if r.get("status") in ("failed", "error")
        ]

        for item in failed:
            analysis = self.analyze_failure(
                test_name=item.get("test_name", "unknown"),
                traceback_str=item.get("traceback_str", "No traceback available."),
                context=json.dumps(item.get("metadata", {})),
            )
            eval_report.failure_analyses.append(analysis)

        if failed:
            if is_mock:
                eval_report.overall_summary = f"{len(failed)} defect(s) detected. AI review unavailable — Ollama offline."
            else:
                severities = [a.severity for a in eval_report.failure_analyses]
                critical = severities.count("critical")
                high = severities.count("high")
                eval_report.overall_summary = (
                    f"Evaluated {len(failed)} defect(s): "
                    f"{critical} critical severity, {high} high severity. "
                    f"{'Deployment gate blocked due to identified critical severity defects.' if critical else 'Review and remediation recommended prior to sign-off.'}"
                )
        else:
            eval_report.overall_summary = "All verification test cases passed successfully. Zero defects identified."

        return eval_report
