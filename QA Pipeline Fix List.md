# Fix list for market-readiness-qa-pipeline

Work top to bottom. Tick each box when it's done; your ticks are saved in this browser.

18 / 18 done

## 1 · Make the scores true critical

- [x] Remove the `try/except: pass` from generated tests so they can actually failcore/source_analyzer.py · TestGenerator
- [x] Use only the project's own tests for the reliability score; show generated tests as a separate "smoke" numbercore/market_readiness_engine.py · evaluate()
- [x] Compare dependency versions with `packaging.version` before flaggingcore/security_scanner.py · \_scan_requirements, \_scan_pom_xml
- [x] Also check `>=`, `~=` and unpinned lines in requirements.txtcore/security_scanner.py · \_scan_requirements

## 2 · Stop running uploads unsafely critical

- [x] Run uploaded code's tests in a subprocess or Docker container (no network, timeout, memory limit)core/source_analyzer.py · analyze_and_test (drop the sys.path insert)
- [x] Swap the `startswith` check for `Path.is_relative_to` and add a max unzipped sizecore/source_analyzer.py · safe_extract_zip

## 3 · Fewer fake or wrong results high

- [x] Mark API and GenAI pillars "not evaluated" instead of giving 100, and re-weight the restcore/market_readiness_engine.py · pillars IV and V
- [x] Show "AI review unavailable" when Ollama is off, instead of mock CVSS 8.5 resultscore/ai_agent_evaluator.py · \_resolve_client, MockLLMClient
- [x] Stop regex rules matching strings and comments: use bandit or AST checks for Pythoncore/security_scanner.py · scan_file
- [x] Replace the hardcoded 15-package CVE list with pip-audit or the OSV databasecore/security_scanner.py · \_KNOWN_VULNERABLE_PACKAGES

## 4 · Make the README match the code medium

- [x] Change "40+ SAST rules" to the real count (18 today)README.md
- [x] Remove Node.js, Go and Docker test runners from the table, or label them "planned"README.md · Supported Archetypes
- [x] Call the model a "prompted specialist" instead of "fine-tuned" (or really train it)README.md · fine_tuning/
- [x] Rename "cryptographic signature" to "integrity checksum", or sign with HMAC / Ed25519README.md · market_readiness_engine.py step 9

## 5 · Clean up the repo low

- [x] Delete and gitignore `tests/generated/`, `reports/` and the sample ZIPs.gitignore
- [x] Add a GitHub Actions workflow that runs the tests and scans the repo itself.github/workflows/ci.yml

## 6 · Prove it works big win

- [x] Build 15–20 small sample repos with known planted bugs, plus a few clean onesbenchmark/
- [x] Measure how many bugs the gate catches and how many false alarms it raises; put the table in the READMEREADME.md · Results

Order matters: sections 1–2 fix wrong answers, 3–4 fix misleading ones, 5–6 make the project convincing.
