from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from backend.config import DEFAULT_MODEL, SPARQL_PUBLIC_ENDPOINT
from backend.llm.llm_models import LLMProvider
from backend.logs.vector_store import search_logs
from backend.patterns import LOG_KEYWORDS, MALWARE_KEYWORDS, THREAT_KEYWORDS, find_cve, find_cwe
from backend.pipeline.prompts import system_prompt_for
from backend.sparql.client import PREFIXES, SPARQLConfig, VirtuosoClient, bindings_to_rows
from backend.sparql.graph_context import build_attack_chain_context
from backend.sparql.nl2sparql import generate_sparql, run_kg_query
from backend.threat.modul_threat import get_malware_context, get_threat_context
from backend.threat.modul_vulnerability import get_vuln_context

def _local_name(uri: str) -> str:
    parts = re.split(r"[#/]", uri.rstrip("#/"))
    return parts[-1] if parts and parts[-1] else uri


def query_router(mode: str, message: str) -> Dict[str, bool]:
    """Tentukan sumber data berdasarkan mode + isi pertanyaan (Issue #04)."""
    q = message.lower()
    want_kg = mode in ("threat_intelligence", "combined")
    want_logs = mode in ("log_analysis", "combined") or any(kw in q for kw in LOG_KEYWORDS)
    return {"kg": want_kg, "logs": want_logs}

def _cve_triples(cve_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Relasi CVE dari endpoint SEPSES publik untuk visualisasi graph (Issue #03)."""
    try:
        client = VirtuosoClient(
            SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False)
        )
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cve cve:id "{cve_id}" .
            ?cve ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))
        return [
            {
                "subject": cve_id,
                "predicate": _local_name(r.get("p", "")),
                "object": _local_name(r.get("o", "")),
                "source": SPARQL_PUBLIC_ENDPOINT,
            }
            for r in rows
        ]
    except Exception:
        return []

def _cwe_triples(cwe_id: str, limit: int = 25) -> List[Dict[str, str]]:
    try:
        client = VirtuosoClient(
            SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False)
        )
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cwe cwe:id "{cwe_id}" .
            ?cwe ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))
        return [
            {
                "subject": cwe_id,
                "predicate": _local_name(r.get("p", "")),
                "object": _local_name(r.get("o", "")),
                "source": SPARQL_PUBLIC_ENDPOINT,
            }
            for r in rows
        ]
    except Exception:
        return []
    
def _kg_retrieve(message: str, model: str) -> Dict[str, Any]:
    """Retrieval dari knowledge graph (Issue #03): konteks, triples, sources, sparql, method."""
    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None

    q = message.lower()

    # --- Enrichment human-readable untuk pola yang dikenal (regex/keyword default) ---
    cve_id = find_cve(message)
    cwe_id = find_cwe(message)
    if cve_id:
        try:
            parts.append(get_vuln_context(cve_id))
            parts.append(build_attack_chain_context(cve_id))
            sources.append(SPARQL_PUBLIC_ENDPOINT)
        except Exception as e:
            parts.append(f"[vuln lookup gagal: {e}]")
        triples.extend(_cve_triples(cve_id))
        
    if cwe_id and not cve_id:
        triples.extend(_cwe_triples(cwe_id))
        sources.append(SPARQL_PUBLIC_ENDPOINT)

    if any(kw in q for kw in THREAT_KEYWORDS):
        kw = next(kw for kw in THREAT_KEYWORDS if kw in q)
        parts.append(get_threat_context(kw))
        sources.append("MITRE ATT&CK")

    if any(kw in q for kw in MALWARE_KEYWORDS):
        kw = next(kw for kw in MALWARE_KEYWORDS if kw in q)
        parts.append(get_malware_context(kw))
        sources.append("MITRE ATT&CK")

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
    for item in history or []:
        role = (item.get("role") or "").lower()
        content = item.get("content") or ""
        if not content:
            continue
        if role == "user":
            msgs.append(HumanMessage(content=content))
        elif role == "assistant":
            msgs.append(AIMessage(content=content))
    return msgs


def answer(
    message: str,
    mode: str = "threat_intelligence",
    model: str = DEFAULT_MODEL,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
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
        user_msg = (
            f"Pertanyaan: {message}\n"
            "(Tidak ada data spesifik ditemukan di knowledge graph untuk pertanyaan ini.)"
        )

    resolved_model = model
    try:
        llm = LLMProvider.get_model(model)
        # Bila model = auto-cheapest, tampilkan model nyata yang terpilih.
        resolved_model = getattr(llm, "model_name", None) or model
        messages = [SystemMessage(content=system_prompt_for(mode))]
        messages.extend(_history_messages(history))
        messages.append(HumanMessage(content=user_msg))
        resp = llm.invoke(messages)
        answer_text = resp.content
    except Exception as e:
        answer_text = f"⚠️ Gagal memanggil LLM ({model}): {e}"

    return {
        "message": answer_text,
        "triples": triples,
        "llmUsed": resolved_model,
        "sources": list(dict.fromkeys(sources)),
        "method": method,      # explainability: regex | llm | None
        "sparql": sparql_used,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(answer("Apa bahaya dari CVE-2017-0144?"), indent=2, ensure_ascii=False))