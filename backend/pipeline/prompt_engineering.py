from __future__ import annotations

import re
from typing import Dict

from backend.logs.vector_store import search_logs
from backend.pipeline.orchestrator import (LOG_KEYWORDS, MALWARE_KEYWORDS, SYSTEM_PROMPT, THREAT_KEYWORDS)
from backend.threat.modul_threat import get_malware_context, get_threat_context
from backend.threat.modul_vulnerability import get_vuln_context

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# System prompt untuk LLM
SYSTEM_PROMPT = """Kamu adalah analis keamanan siber yang ahli.
Jawab pertanyaan pengguna HANYA berdasarkan konteks data yang diberikan.
Jangan mengarang informasi di luar konteks.
Berikan jawaban yang jelas, terstruktur, dan actionable.
Jika data tidak tersedia, katakan dengan jujur."""

def build_prompt(user_question: str) -> Dict[str, str]:
    """Deteksi jenis pertanyaan, ambil konteks relevan, bangun prompt siap kirim."""
    q = user_question.lower()
    context = ""

    cve_match = CVE_RE.search(user_question)
    if cve_match:
        context += get_vuln_context(cve_match.group().upper())

    for kw in THREAT_KEYWORDS:
        if kw in q:
            context += get_threat_context(kw)
            break

    for kw in MALWARE_KEYWORDS:
        if kw in q:
            context += get_malware_context(kw)
            break

    for kw in LOG_KEYWORDS:
        if kw in q:
            context += search_logs(user_question)
            break

    if context:
        user_message = f"Konteks data keamanan:\n{context}\n\nPertanyaan: {user_question}"
    else:
        user_message = (f"Pertanyaan: {user_question}\n"
                        "(Tidak ada data spesifik ditemukan di knowledge graph untuk pertanyaan ini.)")

    return {"system": SYSTEM_PROMPT, "user": user_message}

# Test
if __name__ == "__main__":
    pertanyaan = [
        "Apa bahaya dari CVE-2017-0144?",
        "Ceritakan tentang APT28",
        "Apa itu WannaCry dan bagaimana cara kerjanya?",
        "Ada log mencurigakan terkait reverse shell tidak?",
    ]

    for p in pertanyaan:
        print(f"\nPERTANYAAN: {p}")
        print("-" * 50)
        hasil = build_prompt(p)
        print("SYSTEM:", hasil["system"][:80], "...")
        print("USER MSG:\n", hasil["user"])
        print("=" * 60)