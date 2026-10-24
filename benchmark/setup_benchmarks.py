"""
Benchmark Suite Generator for Market Readiness QA Pipeline.
Generates 18 self-contained benchmark targets (3 clean + 15 with planted bugs).
"""

import os
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent

BENCHMARKS = [
    # Clean projects
    {
        "name": "bench_01_clean_calculator",
        "description": "Clean math utility with full type hints and passing test",
        "expected_gate": "MARKET_READY_APPROVED",
        "expected_flaws": 0,
        "files": {
            "calculator.py": '''"""Clean math calculator."""

def add(a: float, b: float) -> float:
    return a + b

def multiply(a: float, b: float) -> float:
    return a * b
''',
            "test_calculator.py": '''from calculator import add, multiply

def test_add():
    assert add(2, 3) == 5

def test_multiply():
    assert multiply(3, 4) == 12
''',
        },
    },
    {
        "name": "bench_02_clean_web_api",
        "description": "Clean FastAPI route definitions with parameter validation",
        "expected_gate": "MARKET_READY_APPROVED",
        "expected_flaws": 0,
        "files": {
            "app.py": '''"""Clean API service."""
from typing import Dict

def get_status() -> Dict[str, str]:
    return {"status": "healthy", "service": "api"}
''',
            "test_app.py": '''from app import get_status

def test_get_status():
    res = get_status()
    assert res["status"] == "healthy"
''',
        },
    },
    {
        "name": "bench_03_clean_text_utils",
        "description": "Clean text transformations with complete boundary checks",
        "expected_gate": "MARKET_READY_APPROVED",
        "expected_flaws": 0,
        "files": {
            "text_utils.py": '''"""Clean string transformation library."""

def slugify(text: str) -> str:
    return text.strip().lower().replace(" ", "-")

def truncate(text: str, max_len: int = 100) -> str:
    return text[:max_len]
''',
            "test_text_utils.py": '''from text_utils import slugify, truncate

def test_slugify():
    assert slugify("Hello World") == "hello-world"

def test_truncate():
    assert len(truncate("abcdefgh", 4)) == 4
''',
        },
    },

    # Security vulnerabilities (SAST & Secrets)
    {
        "name": "bench_04_cmd_injection_system",
        "description": "Planted Command Injection via os.system with shell=True / dynamic formatting",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "cmd_runner.py": '''import os

def ping_host(host: str):
    # Planted vulnerability: dynamic command string formatted into os.system
    return os.system(f"ping -c 1 {host}")
''',
        },
    },
    {
        "name": "bench_05_cmd_injection_popen",
        "description": "Planted Command Injection via subprocess.Popen(shell=True)",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "sub_runner.py": '''import subprocess

def execute_user_script(script_cmd: str):
    # Planted vulnerability: subprocess with shell=True
    return subprocess.Popen(script_cmd, shell=True)
''',
        },
    },
    {
        "name": "bench_06_eval_rce",
        "description": "Planted Remote Code Execution via eval()",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "eval_engine.py": '''def compute_expression(expr: str):
    # Planted vulnerability: dangerous eval
    return eval(expr)
''',
        },
    },
    {
        "name": "bench_07_sql_injection",
        "description": "Planted SQL Injection via raw string formatting in cursor execute",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "db_service.py": '''def query_user(cursor, username: str):
    # Planted vulnerability: SQL formatted query
    return cursor.execute(f"SELECT * FROM users WHERE username = {username}")
''',
        },
    },
    {
        "name": "bench_08_insecure_pickle",
        "description": "Planted Insecure Deserialization via pickle.loads",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "session_store.py": '''import pickle

def restore_session(payload: bytes):
    # Planted vulnerability: pickle.loads on unvalidated bytes
    return pickle.loads(payload)
''',
        },
    },
    {
        "name": "bench_09_insecure_yaml",
        "description": "Planted Arbitrary Object Instantiation via yaml.load",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "config_parser.py": '''import yaml

def parse_config(data: str):
    # Planted vulnerability: yaml.load with unsafe Loader
    return yaml.load(data, Loader=yaml.Loader)
''',
        },
    },
    {
        "name": "bench_10_weak_crypto_md5",
        "description": "Planted Weak Cryptography via hashlib.md5",
        "expected_gate": "CONDITIONAL_APPROVAL",
        "expected_flaws": 1,
        "files": {
            "hasher.py": '''import hashlib

def hash_token(token: str) -> str:
    # Planted vulnerability: MD5 hash algorithm
    return hashlib.md5(token.encode()).hexdigest()
''',
        },
    },
    {
        "name": "bench_11_path_traversal",
        "description": "Planted Path Traversal in direct open() concatenation",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "file_server.py": '''def read_user_file(filename: str):
    # Planted vulnerability: unvalidated file path concatenation
    with open(f"/app/storage/{filename}", "r") as f:
        return f.read()
''',
        },
    },
    {
        "name": "bench_12_hardcoded_aws_key",
        "description": "Planted Hardcoded AWS Access Key ID",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "s3_client.py": '''# Planted vulnerability: AWS access key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
''',
        },
    },
    {
        "name": "bench_13_hardcoded_api_secret",
        "description": "Planted High-Entropy Secret Key",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "auth.py": '''# Planted vulnerability: High-entropy secret token
api_secret_key = "a1b2c3d4e5f67890a1b2c3d4e5f67890"
''',
        },
    },
    {
        "name": "bench_14_debug_mode_prod",
        "description": "Planted Debug Mode enabled in production configuration",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "settings.py": '''# Planted vulnerability: DEBUG mode active
DEBUG = True
''',
        },
    },
    {
        "name": "bench_15_wildcard_cors",
        "description": "Planted Wildcard CORS configuration",
        "expected_gate": "CONDITIONAL_APPROVAL",
        "expected_flaws": 1,
        "files": {
            "cors_config.py": '''# Planted vulnerability: wildcard origins
allow_origins = ["*"]
''',
        },
    },
    {
        "name": "bench_16_vuln_dep_requests",
        "description": "Planted Outdated Dependency: requests==2.25.0 (CVE-2023-32681)",
        "expected_gate": "CONDITIONAL_APPROVAL",
        "expected_flaws": 1,
        "files": {
            "requirements.txt": '''requests==2.25.0
''',
        },
    },
    {
        "name": "bench_17_vuln_dep_aiohttp",
        "description": "Planted Critical Vulnerable Dependency: aiohttp==3.8.1 (CVE-2024-23334)",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "requirements.txt": '''aiohttp==3.8.1
''',
        },
    },
    {
        "name": "bench_18_failing_unit_test",
        "description": "Planted Broken Business Logic causing functional test failure",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "finance.py": '''def compute_tax(amount: float) -> float:
    # Planted bug: negative tax calculation
    return -amount * 0.2
''',
            "test_finance.py": '''from finance import compute_tax

def test_compute_tax_positive():
    assert compute_tax(100.0) == 20.0
''',
        },
    },
    {
        "name": "bench_19_mixed_test_results",
        "description": "Mixed Suite: 3 passing unit tests and 1 failing functional assertion",
        "expected_gate": "MARKET_BLOCKED",
        "expected_flaws": 1,
        "files": {
            "math_ops.py": '''def add(a, b): return a + b
def sub(a, b): return a - b
def mul(a, b): return a * b
def div(a, b): return a + b  # Planted bug: returns sum instead of quotient
''',
            "test_math_ops.py": '''from math_ops import add, sub, mul, div

def test_add_ok():
    assert add(10, 5) == 15

def test_sub_ok():
    assert sub(10, 5) == 5

def test_mul_ok():
    assert mul(10, 5) == 50

def test_div_fails():
    assert div(10, 5) == 2  # Fails!
''',
        },
    },
]

def generate_benchmark_targets():
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    for bench in BENCHMARKS:
        target_dir = BENCHMARK_DIR / bench["name"]
        target_dir.mkdir(parents=True, exist_ok=True)
        for rel_path, content in bench["files"].items():
            fpath = target_dir / rel_path
            fpath.write_text(content, encoding="utf-8")
    print(f"Generated {len(BENCHMARKS)} benchmark targets in {BENCHMARK_DIR}")

if __name__ == "__main__":
    generate_benchmark_targets()
