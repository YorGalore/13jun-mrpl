from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from backend.config import DEFAULT_MODEL, SUPPORTED_MODEL_NAMES
from backend.llm.llm_models import LLMProvider
from backend.patterns import (
    LOG_KEYWORDS,
    MALWARE_KEYWORDS,
    MITRE_GENERAL_KEYWORDS,
    THREAT_KEYWORDS,
    extract_actor_name,
    find_cve,
    find_cwe,
)
from backend.pipeline.prompts import system_prompt_for
from backend.sources import logs, mitre, sparql

MAX_CONTEXT_CHARS = 6000


def _route(mode: str, message: str) -> Dict[str, bool]:
    q = message.lower()
    return {
        "kg": mode in ("threat_intelligence", "combined"),
        "logs": mode in ("log_analysis", "combined") or any(k in q for k in LOG_KEYWORDS),
        "mitre_general": any(k in q for k in MITRE_GENERAL_KEYWORDS),
    }


def _collect_context(message: str, mode: str, model: str) -> Dict[str, Any]:
    route = _route(mode, message)
    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None
    q = message.lower()
 
    if route["kg"]:
        # --- SEPSES (sparql gateway) ---
        cve_id = find_cve(message)
        cwe_id = find_cwe(message)
        if cve_id:
            try:
                parts.append(sparql.vuln_context(cve_id))
                parts.append(sparql.attack_chain_context(cve_id))
                triples.extend(sparql.cve_triples(cve_id))
                sources.append("SEPSES CSKG (publik)")
            except Exception as e:
                print(f"[orch] sparql CVE gagal: {e}")
        if cwe_id and not cve_id:
            try:
                triples.extend(sparql.cwe_triples(cwe_id))
                sources.append("SEPSES CSKG (publik)")
            except Exception as e:
                print(f"[orch] sparql CWE gagal: {e}")
 
        # --- MITRE (mitre gateway) ---
        if any(k in q for k in THREAT_KEYWORDS):
            actor = extract_actor_name(message)
            if actor:
                try:
                    parts.append(mitre.threat_context(actor))
                    sources.append("MITRE ATT&CK")
                except Exception as e:
                    print(f"[orch] mitre threat gagal: {e}")
        if any(k in q for k in MALWARE_KEYWORDS):
            kw = max((k for k in MALWARE_KEYWORDS if k in q), key=len, default=None)
            if kw:
                try:
                    parts.append(mitre.malware_context(kw))
                    sources.append("MITRE ATT&CK")
                except Exception as e:
                    print(f"[orch] mitre malware gagal: {e}")
        if route["mitre_general"]:
            try:
                ctx = mitre.technique_context(message)
                if ctx:
                    parts.append(ctx)
                    sources.append("MITRE ATT&CK (Techniques)")
            except Exception as e:
                print(f"[orch] mitre technique gagal: {e}")
 
 
        if cve_id or cwe_id:
            try:
                sparql_used, method = sparql.generate_sparql(message, model=model)
                rows = sparql.run_query(sparql_used)
                if rows:
                    preview = rows[:10]
                    lines = [" | ".join(f"{k}: {v}" for k, v in r.items()) for r in preview]
                    parts.append("=== Hasil SPARQL (KG) ===\n" + "\n".join(lines))
                    sources.append("SEPSES CSKG (SPARQL)")
            except Exception as e:
                print(f"[orch] nl2sparql gagal: {e}")
 
    elif route["mitre_general"]:
        try:
            ctx = mitre.technique_context(message)
            if ctx:
                parts.append(ctx)
                sources.append("MITRE ATT&CK (Techniques)")
        except Exception as e:
            print(f"[orch] mitre technique gagal: {e}")
 
    if route["logs"]:
        try:
            result = logs.search_logs(message)
            if result:
                parts.append(result)
            sources.append("Log keamanan lokal (ChromaDB)")
        except Exception as e:
            print(f"[orch] log search gagal: {e}")
 
    context = "\n\n".join(p for p in parts if p)
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[:MAX_CONTEXT_CHARS] + "\n…[konteks dipotong]"
 
    return {
        "context": context,
        "sources": list(dict.fromkeys(sources)),
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

def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
        return "".join(parts).strip()
    if content is None:
        return ""
    return str(content)
 
 
def _failure_hint(model: str, err: Exception) -> str:
    if not model.lower().startswith("ollama"):
        return ""
    e = str(err).lower()
    if any(k in e for k in ("connection", "connect", "refused", "max retries", "timed out", "timeout")):
        return ("\n\nPetunjuk: pastikan Ollama berjalan (`ollama serve`) dan OLLAMA_BASE_URL benar "
                "(host: http://localhost:11434 ; di Docker: http://host.docker.internal:11434).")
    if any(k in e for k in ("not found", "no such model", "pull", "model")):
        model_id = model.split(":", 1)[1] if ":" in model else model
        return f"\n\nPetunjuk: model belum tersedia. Jalankan: `ollama pull {model_id}`."
    return ""


def _synthesize(context: str, message: str, mode: str, model: str, history=None) -> Dict[str, Any]:
    if context:
        user_msg = f"Konteks data keamanan:\n{context}\n\nPertanyaan: {message}"
    else:
        user_msg = (
            f"Pertanyaan: {message}\n"
            "(Tidak ada data spesifik di KG/MITRE/log. Jawab berdasarkan pengetahuan umum keamanan siber.)"
        )

    resolved = model
    try:
        llm = LLMProvider.get_model(model)
        resolved = getattr(llm, "model_name", None) or model
        messages = [SystemMessage(content=system_prompt_for(mode))]
        messages.extend(_history_messages(history))
        messages.append(HumanMessage(content=user_msg))
        resp = llm.invoke(messages)
        return {"message": _text(resp.content), "llmUsed": resolved, "ok": True, "error": None}
    except Exception as e:
        msg = (
            f"⚠️ Model '{model}' gagal menjawab: {e}{_failure_hint(model, e)}\n\n"
            + (f"Konteks yang berhasil diambil:\n{context}" if context else "")
        )
        return {"message": msg, "llmUsed": resolved, "ok": False, "error": str(e)}

def answer(message: str, mode: str = "threat_intelligence", model: str = DEFAULT_MODEL, history=None) -> Dict[str, Any]:
    ctx = _collect_context(message, mode, model)
    syn = _synthesize(ctx["context"], message, mode, model, history)
    return {
        "message": syn["message"],
        "triples": ctx["triples"],
        "llmUsed": syn["llmUsed"],
        "sources": ctx["sources"],
        "method": ctx["method"],
        "sparql": ctx["sparql"],
    }


def compare(message: str, models=None, mode: str = "threat_intelligence", history=None) -> Dict[str, Any]:
    use_models = [m for m in (models or list(SUPPORTED_MODEL_NAMES)) if m] or [DEFAULT_MODEL]
    # Retrieval SEKALI; konteks dipakai bersama agar perbandingan adil.
    ctx = _collect_context(message, mode, use_models[0])

    answers = []
    for m in use_models:
        start = time.perf_counter()
        syn = _synthesize(ctx["context"], message, mode, m, history)
        answers.append({
            "model": m,
            "llmUsed": syn["llmUsed"],
            "message": syn["message"],
            "ok": syn["ok"],
            "error": syn["error"],
            "latencySec": round(time.perf_counter() - start, 3),
        })

    return {
        "question": message,
        "mode": mode,
        "answers": answers,
        "triples": ctx["triples"],
        "sources": ctx["sources"],
        "method": ctx["method"],
        "sparql": ctx["sparql"],
    }