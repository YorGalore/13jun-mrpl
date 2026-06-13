from __future__ import annotations

from typing import Dict, List

TEST_CASES: List[Dict[str, str]] = [
    {"question": "Show information about CVE-2021-44228", "category": "cve", "expect": "regex"},
    {"question": "List vulnerabilities with critical severity", "category": "severity", "expect": "fallback_keyword"},
    {"question": "Find attack patterns related to SQL Injection", "category": "capec", "expect": "llm"},
    {"question": "Show malware targeting Apache servers", "category": "general", "expect": "llm"},
    {"question": "Find techniques used by ransomware groups", "category": "general", "expect": "llm"},
    {"question": "Show CAPEC attack patterns", "category": "capec", "expect": "llm"},
    {"question": "List vulnerabilities related to buffer overflow", "category": "general", "expect": "llm"},
    {"question": "Find attack techniques targeting Windows systems", "category": "general", "expect": "llm"},
    {"question": "Show all published CVEs in 2021", "category": "general", "expect": "llm"},
    {"question": "Find relationships between CVE and CWE", "category": "cwe_relation", "expect": "llm"},
]
TEST_QUESTIONS: List[str] = [c["question"] for c in TEST_CASES]