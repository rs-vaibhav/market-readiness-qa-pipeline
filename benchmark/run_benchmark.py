"""
Benchmark Evaluation Runner.
Runs the Market Readiness QA Pipeline on all 18 benchmark test targets,
evaluates precision, recall, and gate decision accuracy, and outputs a formatted table.
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.market_readiness_engine import MarketReadinessEngine
from benchmark.setup_benchmarks import BENCHMARKS, BENCHMARK_DIR

def run_benchmarks():
    engine = MarketReadinessEngine()
    results = []

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    print("=" * 80)
    print("EXECUTING QA PIPELINE BENCHMARK (18 TARGETS)")
    print("=" * 80)

    for bench in BENCHMARKS:
        target_dir = BENCHMARK_DIR / bench["name"]
        is_clean = bench["expected_flaws"] == 0

        report = engine.evaluate(target_dir, run_functional_tests=True)
        sec_findings = report.security_summary.get("total_findings", 0) if report.security_summary else 0
        test_failures = report.test_summary.get("failed", 0) if report.test_summary else 0
        total_flaws_caught = sec_findings + test_failures
        decision = report.gate_decision
        score = report.market_readiness_score

        # Verification logic
        if is_clean:
            if total_flaws_caught == 0 and decision == "MARKET_READY_APPROVED":
                status = "PASS (TN)"
                true_negatives += 1
            else:
                status = "FAIL (FP)"
                false_positives += 1
        else:
            if total_flaws_caught >= bench["expected_flaws"] and decision != "MARKET_READY_APPROVED":
                status = "PASS (TP)"
                true_positives += 1
            elif total_flaws_caught >= bench["expected_flaws"] and bench["expected_gate"] == "CONDITIONAL_APPROVAL":
                status = "PASS (TP)"
                true_positives += 1
            else:
                status = "FAIL (FN)"
                false_negatives += 1

        record = {
            "name": bench["name"],
            "type": "Clean" if is_clean else "Planted Bug",
            "expected_gate": bench["expected_gate"],
            "actual_gate": decision,
            "score": score,
            "flaws_detected": total_flaws_caught,
            "status": status,
        }
        results.append(record)
        print(f"[{status:9s}] {bench['name']:32s} | Score: {score:5.1f} | Gate: {decision}")

    total = len(results)
    precision = true_positives / max(true_positives + false_positives, 1) * 100.0
    recall = true_positives / max(true_positives + false_negatives, 1) * 100.0
    accuracy = (true_positives + true_negatives) / total * 100.0

    print("\n" + "=" * 80)
    print("BENCHMARK METRICS SUMMARY")
    print("=" * 80)
    print(f"Total Targets:     {total}")
    print(f"True Positives:    {true_positives} / 15 (Planted defects caught)")
    print(f"True Negatives:    {true_negatives} / 3  (Clean projects passed without false alarm)")
    print(f"False Positives:   {false_positives} (False alarms on clean code)")
    print(f"False Negatives:   {false_negatives} (Planted defects missed)")
    print(f"Precision:         {precision:.1f}%")
    print(f"Recall:            {recall:.1f}%")
    print(f"Accuracy:          {accuracy:.1f}%")

    # Generate Markdown Table for README
    md_lines = [
        "### Empirical Benchmark Results",
        "",
        "The gatekeeper was rigorously evaluated across a standardized benchmark suite of 18 repositories (3 clean baseline projects and 15 containing known planted security, architectural, and reliability defects).",
        "",
        "| ID | Benchmark Target | Archetype / Flaw | Expected Gate | Actual Gate | Quality Index | Result |",
        "|:---|:---|:---|:---|:---|:---:|:---:|",
    ]

    for idx, r in enumerate(results, start=1):
        clean_name = r["name"].replace("bench_", "")
        md_lines.append(
            f"| {idx:02d} | `{clean_name}` | {r['type']} | {r['expected_gate']} | {r['actual_gate']} | {r['score']}% | {r['status'].split()[0]} |"
        )

    md_lines.extend([
        "",
        f"**Benchmark Performance Summary**:",
        f"- **Defect Detection Recall**: {recall:.1f}% ({true_positives}/15 planted defects caught)",
        f"- **Clean Code Precision**: {precision:.1f}% ({false_positives} false positives on clean codebases)",
        f"- **Overall Gate Determination Accuracy**: {accuracy:.1f}% ({true_positives + true_negatives}/{total} correct determinations)",
    ])

    markdown_output = "\n".join(md_lines)
    output_path = BENCHMARK_DIR / "BENCHMARK_RESULTS.md"
    output_path.write_text(markdown_output, encoding="utf-8")
    print(f"\nSaved benchmark markdown report to {output_path}")

    return markdown_output

if __name__ == "__main__":
    run_benchmarks()
