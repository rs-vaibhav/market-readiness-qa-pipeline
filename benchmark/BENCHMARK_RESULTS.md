### Empirical Benchmark Results

The gatekeeper was rigorously evaluated across a standardized benchmark suite of 18 repositories (3 clean baseline projects and 15 containing known planted security, architectural, and reliability defects).

| ID | Benchmark Target | Archetype / Flaw | Expected Gate | Actual Gate | Quality Index | Result |
|:---|:---|:---|:---|:---|:---:|:---:|
| 01 | `01_clean_calculator` | Clean | MARKET_READY_APPROVED | MARKET_READY_APPROVED | 99.1% | PASS |
| 02 | `02_clean_web_api` | Clean | MARKET_READY_APPROVED | MARKET_READY_APPROVED | 99.1% | PASS |
| 03 | `03_clean_text_utils` | Clean | MARKET_READY_APPROVED | MARKET_READY_APPROVED | 99.1% | PASS |
| 04 | `04_cmd_injection_system` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 76.4% | PASS |
| 05 | `05_cmd_injection_popen` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 72.4% | PASS |
| 06 | `06_eval_rce` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 72.4% | PASS |
| 07 | `07_sql_injection` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 72.4% | PASS |
| 08 | `08_insecure_pickle` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 72.4% | PASS |
| 09 | `09_insecure_yaml` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 76.4% | PASS |
| 10 | `10_weak_crypto_md5` | Planted Bug | CONDITIONAL_APPROVAL | CONDITIONAL_APPROVAL | 80.4% | PASS |
| 11 | `11_path_traversal` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 75.5% | PASS |
| 12 | `12_hardcoded_aws_key` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 73.3% | PASS |
| 13 | `13_hardcoded_api_secret` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 73.3% | PASS |
| 14 | `14_debug_mode_prod` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 77.3% | PASS |
| 15 | `15_wildcard_cors` | Planted Bug | CONDITIONAL_APPROVAL | CONDITIONAL_APPROVAL | 81.3% | PASS |
| 16 | `16_vuln_dep_requests` | Planted Bug | CONDITIONAL_APPROVAL | CONDITIONAL_APPROVAL | 81.3% | PASS |
| 17 | `17_vuln_dep_aiohttp` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 73.3% | PASS |
| 18 | `18_failing_unit_test` | Planted Bug | MARKET_BLOCKED | MARKET_BLOCKED | 65.7% | PASS |

**Benchmark Performance Summary**:
- **Defect Detection Recall**: 100.0% (15/15 planted defects caught)
- **Clean Code Precision**: 100.0% (0 false positives on clean codebases)
- **Overall Gate Determination Accuracy**: 100.0% (18/18 correct determinations)