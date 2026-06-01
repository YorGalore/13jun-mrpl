"""
RAG/GraphRAG orchestrator.
Lebur dari modul_a3/prompt_engineering.py (routing konteks) + modul_a3/use_case.py (alur).
Sumber: kontribusi modul_a3 (anggota tim) — disatukan di backend/pipeline/.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from backend.config import DEFAULT_MODEL, SPARQL_PUBLIC_ENDPOINT
from backend.llm.llm_models import LLMProvider
from backend.logs.vector_store import search_logs
from backend.sparql.client import (PREFIXES, SPARQLConfig, VirtuosoClient, bindings_to_rows)
from backend.sparql.nl2sparql import generate_sparql, run_kg_query
from backend.threat.modul_threat import get_malware_context, get_threat_context
from backend.threat.modul_vulnerability import get_vuln_context

SYSTEM_PROMPT = """Kamu adalah analis keamanan siber yang ahli.
Jawab pertanyaan pengguna HANYA berdasarkan konteks data yang diberikan.
Jangan mengarang informasi di luar konteks.
Berikan jawaban yang jelas, terstruktur, dan actionable.
Jika data tidak tersedia, katakan dengan jujur."""

THREAT_KEYWORDS = ["apt", "lazarus", "fancy bear", "cozy bear", "kimsuky", "sandworm", "carbanak", "fin7", "turla"]
MALWARE_KEYWORDS = ["wannacry", "emotet", "mirai", "stuxnet", "notpetya", "ransomware", "trojan", "rootkit", "cobalt strike"]
LOG_KEYWORDS = ["log", "ssh", "login", "failed", "connection", "brute", "intrusion", "anomali", "mencurigakan", "reverse shell", "port scan"]

CVE_RE = re.compile(r"cve-\d{4}-\d+", re.IGNORECASE)

def _local_name(uri: str) -> str:
    parts = re.split(r"[#/]", uri.rstrip("#/"))
    return parts[-1] if parts and parts[-1] else uri

def query_router(mode: str, message: str) -> Dict[str, bool]:
    """Tentukan sumber data yang dipakai berdasarkan mode + isi pertanyaan (Issue #04)."""
    q = message.lower()
    want_kg = mode in ("threat_intelligence", "combined")
    want_logs = mode == "log_analysis" or mode == "combined" \
        or any(kw in q for kw in LOG_KEYWORDS)
    return {"kg": want_kg, "logs": want_logs}


def _cve_triples(cve_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Ambil relasi CVE dari endpoint SEPSES publik untuk visualisasi graph."""
    try:


        client = VirtuosoClient(SPARQLConfig(
            endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False))
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cve cve:id "{cve_id}" .
            ?cve ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))
        
        return [
            {"subject": cve_id, "predicate": _local_name(r.get("p", "")),
             "object": _local_name(r.get("o", "")), "source": SPARQL_PUBLIC_ENDPOINT}
            for r in rows
        ]
    except Exception:
        return []

def _kg_retrieve(message: str, model: str) -> Dict[str, Any]:
    """
    Retrieval dari knowledge graph (Issue #03).
    Mengembalikan: konteks teks, triples, sources, sparql, method.
    """
    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None

    q = message.lower()

    # --- Enrichment human-readable untuk pola yang dikenal ---
    cve_match = CVE_RE.search(message)
    if cve_match:
        cve_id = cve_match.group().upper()
        try:
            parts.append(get_vuln_context(cve_id))
            sources.append(SPARQL_PUBLIC_ENDPOINT)
        except Exception as e:
            parts.append(f"[vuln lookup gagal: {e}]")
        triples.extend(_cve_triples(cve_id))

    for kw in THREAT_KEYWORDS:
        if kw in q:
            parts.append(get_threat_context(kw))
            sources.append("MITRE ATT&CK")
            break

    for kw in MALWARE_KEYWORDS:
        if kw in q:
            parts.append(get_malware_context(kw))
            sources.append("MITRE ATT&CK")
            break

    # --- NL2SPARQL: jalur generik (regex fast-path di dalamnya, lalu LLM) ---
    try:
        sparql_used, method = generate_sparql(message, model=model)
        rows = run_kg_query(sparql_used)
        if rows:
            preview = rows[:10]
            lines = [" | ".join(f"{k}: {v}" for k, v in row.items()) for row in preview]
            parts.append("=== Hasil SPARQL (KG) ===\n" + "\n".join(lines))
            sources.append("SEPSES CSKG (SPARQL)")
    except Exception as e:
        parts.append(f"[NL2SPARQL gagal: {e}]")

    return {
        "context": "\n\n".join(p for p in parts if p),
        "sources": sources,
        "triples": triples,
        "sparql": sparql_used,
        "method": method,
    }


def _history_messages(history: Optional[List[Dict[str, str]]]):
    msgs = []
    for item in (history or []):
        role = (item.get("role") or "").lower()
        content = item.get("content") or ""
        if not content:
            continue
        if role == "user":
            msgs.append(HumanMessage(content=content))
        elif role == "assistant":
            msgs.append(AIMessage(content=content))
    return msgs


def answer(message: str, mode: str = "threat_intelligence",
           model: str = DEFAULT_MODEL,
           history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    route = query_router(mode, message)

    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None

    if route["kg"]:
        kg = _kg_retrieve(message, model)
        if kg["context"]:
            parts.append(kg["context"])
        sources.extend(kg["sources"])
        triples.extend(kg["triples"])
        sparql_used = kg["sparql"]
        method = kg["method"]

    if route["logs"]:
        try:
            parts.append(search_logs(message))
            sources.append("Local security logs (ChromaDB)")
        except Exception as e:
            parts.append(f"[log search gagal: {e}]")

    context = "\n\n".join(p for p in parts if p)
    if context:
        user_msg = f"Konteks data keamanan:\n{context}\n\nPertanyaan: {message}"
    else:
        user_msg = (f"Pertanyaan: {message}\n"
                    "(Tidak ada data spesifik ditemukan di knowledge graph untuk pertanyaan ini.)")

    try:
        llm = LLMProvider.get_model(model)
        messages = [SystemMessage(content=SYSTEM_PROMPT)]
        messages.extend(_history_messages(history))
        messages.append(HumanMessage(content=user_msg))
        resp = llm.invoke(messages)
        answer_text = resp.content
    except Exception as e:
        answer_text = f"⚠️ Gagal memanggil LLM ({model}): {e}"

    return {
        "message": answer_text,
        "triples": triples,
        "llmUsed": model,
        "sources": list(dict.fromkeys(sources)),
        "method": method,     # explainability: regex | llm | None
        "sparql": sparql_used,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(answer("Apa bahaya dari CVE-2017-0144?"), indent=2, ensure_ascii=False))
