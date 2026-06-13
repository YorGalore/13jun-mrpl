from __future__ import annotations

from __future__ import annotations
 
import re
import ssl
from typing import Dict, List, Optional, Tuple
 
from langchain_core.prompts import PromptTemplate
from SPARQLWrapper import JSON, POST, SPARQLWrapper
 
from backend.config import (
    SPARQL_ENABLE_LOCAL_FALLBACK,
    SPARQL_LOCAL_ENDPOINT,
    SPARQL_LOCAL_GRAPH,
    SPARQL_PUBLIC_ENDPOINT,
    SPARQL_TIMEOUT,
)
from backend.llm.llm_models import DEFAULT_MODEL, LLMProvider
from backend.patterns import CVE_RE, CWE_RE

# Beberapa endpoint SEPSES memakai sertifikat yang rewel; lewati verifikasi SSL.
ssl._create_default_https_context = ssl._create_unverified_context

PREFIXES = """\
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX dct:  <http://purl.org/dc/terms/>
PREFIX cve:  <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe:  <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX cpe:  <http://w3id.org/sepses/vocab/ref/cpe#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
"""

# Ontologi ringkas untuk membantu LLM membuat SPARQL (jalur nl2sparql).
ONTOLOGY_CONTEXT = """\
DATA SOURCE: SEPSES public SPARQL endpoint (CVE/CWE/CAPEC/CPE/CVSS).
KEY PROPERTIES:
- cve:id (literal id), dct:description (deskripsi CVE), dct:issued, dct:modified,
  cve:hasCWE, cve:hasCPE, cve:hasCVSS2BaseMetric, cve:hasCVSS3BaseMetric
- cvss:baseScore, cvss:confidentialityImpact, cvss:integrityImpact,
  cvss:availabilityImpact, cvss:attackVector
- cwe:id, cwe:name, cwe:status, dct:description (deskripsi CWE),
  cwe:hasCAPEC, cwe:hasCommonConsequence, cwe:consequenceImpact,
  cwe:hasPotentialMitigation (mitigasi CWE -> node)
- capec:id, capec:name, dct:description (deskripsi CAPEC),
  capec:likelihoodOfAttack, capec:hasMitigation

COMMON SHAPES:
1. ?cve cve:id "CVE-2021-44228" . OPTIONAL { ?cve dct:description ?d . }
2. ?cve cve:hasCWE ?cwe . OPTIONAL { ?cwe cwe:name ?n . } OPTIONAL { ?cwe dct:description ?cd . }
3. ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?s .
4. ?cwe cwe:hasCAPEC ?capec . OPTIONAL { ?capec capec:name ?name . }
   OPTIONAL { ?capec dct:description ?capecDesc . }
"""
 
_FORBIDDEN = re.compile(r"\b(INSERT|DELETE|DROP|CLEAR|LOAD|CREATE|COPY|MOVE|ADD)\b", re.IGNORECASE)


# CORE — eksekutor SPARQL: SEPSES publik dulu, Virtuoso lokal sebagai cadangan
def _wrapper(endpoint: str, graph: Optional[str] = None) -> SPARQLWrapper:
    w = SPARQLWrapper(endpoint)
    w.setReturnFormat(JSON)
    w.setMethod(POST)
    w.setTimeout(SPARQL_TIMEOUT)
    # Untuk Virtuoso lokal, data dimuat ke named graph (mis. http://sepses.local).
    # Set default-graph agar query tanpa klausa GRAPH tetap mengenai data tersebut.
    if graph:
        w.addDefaultGraph(graph)
    return w
 
 
def _exec(endpoint: str, query: str, graph: Optional[str] = None) -> List[Dict[str, str]]:
    w = _wrapper(endpoint, graph)
    w.setQuery(query)
    result = w.query().convert()
    bindings = result.get("results", {}).get("bindings", [])
    return [{k: v.get("value", "") for k, v in row.items()} for row in bindings]
 
 
def run_query(query: str) -> List[Dict[str, str]]:
    """Jalankan SPARQL. Urutan: (1) endpoint publik SEPSES; bila gagal ATAU kosong
    DAN fallback diaktifkan, (2) Virtuoso lokal. Tidak pernah raise -> [] bila semua gagal."""
    # 1) Sumber utama: endpoint publik SEPSES.
    try:
        rows = _exec(SPARQL_PUBLIC_ENDPOINT, query)
        if rows:
            return rows
        # rows kosong: bisa jadi SEPSES memang tidak punya datanya -> lanjut ke fallback.
    except Exception as e:  # endpoint mati / timeout / jaringan
        print(f"[sparql] endpoint publik gagal: {e}")
 
    # 2) Cadangan: Virtuoso lokal (mis. SEPSES down, atau datanya hanya ada di lokal).
    if SPARQL_ENABLE_LOCAL_FALLBACK and SPARQL_LOCAL_ENDPOINT:
        try:
            rows = _exec(SPARQL_LOCAL_ENDPOINT, query, graph=SPARQL_LOCAL_GRAPH)
            if rows:
                print(f"[sparql] fallback Virtuoso lokal dipakai ({SPARQL_LOCAL_ENDPOINT})")
                return rows
        except Exception as e:  # virtuoso belum jalan / belum ada datanya
            print(f"[sparql] fallback lokal gagal: {e}")
 
    return []
 
 
def escape_literal(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
 
 
def _local_name(uri: str) -> str:
    parts = re.split(r"[#/]", (uri or "").rstrip("#/"))
    return parts[-1] if parts and parts[-1] else uri


# VULNERABILITY CONTEXT (eks modul_vulnerability.get_vuln_context)
def vuln_context(cve_id: str) -> str:
    """Ringkasan kerentanan CVE -> CWE -> CAPEC + CVSS sebagai teks untuk LLM."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return ""
 
    query = f"""{PREFIXES}
SELECT DISTINCT ?description ?cweName ?capecName ?mitigation ?confImpact ?cvssScore ?consequenceImpact
WHERE {{
  ?cve cve:id "{escape_literal(cve_id)}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?c3 . ?c3 cvss:baseScore ?cvssScore .
             OPTIONAL {{ ?c3 cvss:confidentialityImpact ?confImpact . }} }}
  OPTIONAL {{ ?cve cve:hasCVSS2BaseMetric ?c2 . ?c2 cvss:baseScore ?cvssScore .
             OPTIONAL {{ ?c2 cvss:confidentialityImpact ?confImpact . }} }}
  OPTIONAL {{
    ?cve cve:hasCWE ?cwe .
    OPTIONAL {{ ?cwe cwe:name ?cweName . }}
    OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec .
               OPTIONAL {{ ?capec capec:name ?capecName . }}
               OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }}
    OPTIONAL {{ ?cwe cwe:hasCommonConsequence ?cc . ?cc cwe:consequenceImpact ?consequenceImpact . }}
  }}
}} LIMIT 200"""
 
    rows = run_query(query)
    if not rows:
        return f"Tidak ada data ditemukan untuk {cve_id} (atau endpoint publik tidak tersedia)."
 
    def first(key: str) -> str:
        return next((r.get(key, "") for r in rows if r.get(key)), "")
 
    def uniq(key: str) -> List[str]:
        return sorted({r.get(key, "") for r in rows if r.get(key)})
 
    description = first("description")
    cvss_score = first("cvssScore")
    conf_impact = first("confImpact")
    cwes = uniq("cweName")
    attacks = uniq("capecName")
    consequences = uniq("consequenceImpact")
    mitigations = [r.get("mitigation", "") for r in rows if r.get("mitigation")]
 
    out = f"=== Informasi Kerentanan {cve_id} ===\n"
    if cvss_score:
        out += f"CVSS Score   : {cvss_score}\n"
    if conf_impact:
        out += f"Conf. Impact : {conf_impact}\n"
    if description:
        out += f"Deskripsi    : {description[:300]}\n"
    if cwes:
        out += f"Weakness     : {', '.join(cwes)}\n"
    if consequences:
        out += f"Dampak       : {', '.join(consequences)}\n"
    if attacks:
        out += f"Pola Serangan: {', '.join(attacks)}\n"
    if mitigations:
        out += f"Mitigasi     : {mitigations[0][:300]}\n"
 
    if out.strip().endswith("==="):
        out += "(CVE ditemukan, namun atribut detail tidak tersedia di KG.)\n"
    return out


# ATTACK CHAIN (eks graph_context.build_attack_chain_context)
def attack_chain_context(cve_id: str) -> str:
    cve_id = (cve_id or "").strip().upper()
    query = f"""{PREFIXES}
SELECT DISTINCT ?description ?score ?cweName ?capecName ?mitigation WHERE {{
  ?cve cve:id "{escape_literal(cve_id)}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
  OPTIONAL {{ ?cve cve:hasCWE ?cwe .
             OPTIONAL {{ ?cwe cwe:name ?cweName . }}
             OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?capecName .
                        OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }} }}
}} LIMIT 50"""
    rows = run_query(query)
    if not rows:
        return f"Tidak ada rantai serangan di KG untuk {cve_id}."
 
    score = next((r["score"] for r in rows if r.get("score")), "")
    description = next((r["description"] for r in rows if r.get("description")), "")
    cwes = sorted({r["cweName"] for r in rows if r.get("cweName")})
    capecs = sorted({r["capecName"] for r in rows if r.get("capecName")})
    mitigation = next((r["mitigation"] for r in rows if r.get("mitigation")), "")
 
    lines = [f"=== Attack Chain {cve_id} ==="]
    if score:
        lines.append(f"CVSS3 Base Score : {score}")
    if description:
        lines.append(f"Deskripsi        : {description[:300]}")
    if cwes:
        lines.append(f"Weakness (CWE)   : {', '.join(cwes)}")
    if capecs:
        lines.append(f"Pola Serangan    : {', '.join(capecs)}  (CWE -> CAPEC)")
    if mitigation:
        lines.append(f"Mitigasi         : {mitigation[:300]}")
    return "\n".join(lines)


# TRIPLES untuk visualisasi graph (eks orchestrator._cve_triples/_cwe_triples)
def _mk(subject: str, predicate: str, obj: str, seen: set, out: List[Dict[str, str]]) -> None:
    obj = (obj or "").strip()
    if not obj:
        return
    key = (subject, predicate, obj)
    if key in seen:
        return
    seen.add(key)
    out.append({"subject": subject, "predicate": predicate, "object": obj, "source": SPARQL_PUBLIC_ENDPOINT})
 
 
def cve_triples(cve_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Triples bermakna untuk visualisasi: CVE -> CWE -> CAPEC + CVSS.
    Dibangun dari rantai serangan (data yang terbukti tersedia), bukan dari
    kueri mentah `?cve ?p ?o` yang sering kosong/berisik."""
    cve_id = (cve_id or "").strip().upper()
    query = f"""{PREFIXES}
SELECT DISTINCT ?cwe ?capec ?score WHERE {{
  ?cve cve:id "{escape_literal(cve_id)}" .
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m3 . ?m3 cvss:baseScore ?score . }}
  OPTIONAL {{ ?cve cve:hasCVSS2BaseMetric ?m2 . ?m2 cvss:baseScore ?score . }}
  OPTIONAL {{ ?cve cve:hasCWE ?cwe . OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . }} }}
}} LIMIT {int(limit)}"""
    rows = run_query(query)
    out: List[Dict[str, str]] = []
    seen: set = set()
    for r in rows:
        if r.get("score"):
            _mk(cve_id, "cvssScore", str(r["score"]), seen, out)
        cwe = _local_name(r.get("cwe", ""))
        if cwe:
            _mk(cve_id, "hasWeakness", cwe, seen, out)
            capec = _local_name(r.get("capec", ""))
            if capec:
                _mk(cwe, "enablesAttack", capec, seen, out)
    return out
 
 
def cwe_triples(cwe_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Triples bermakna untuk CWE -> CAPEC."""
    cwe_id = (cwe_id or "").strip().upper()
    query = f"""{PREFIXES}
SELECT DISTINCT ?capec WHERE {{
  ?cwe cwe:id "{escape_literal(cwe_id)}" .
  OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . }}
}} LIMIT {int(limit)}"""
    rows = run_query(query)
    out: List[Dict[str, str]] = []
    seen: set = set()
    for r in rows:
        capec = _local_name(r.get("capec", ""))
        if capec:
            _mk(cwe_id, "enablesAttack", capec, seen, out)
    return out


# NL -> SPARQL (eks nl2sparql) — regex cepat, lalu LLM, lalu fallback
_PROMPT = PromptTemplate(
    input_variables=["ontology", "question"],
    template=(
        "You are a cybersecurity SPARQL expert.\n"
        "- Translate the question into valid SPARQL using the ontology below.\n"
        "- Use OPTIONAL for properties that may be missing. Include PREFIX. Return ONLY SPARQL.\n\n"
        "Ontology:\n{ontology}\n\nQuestion:\n{question}\n\nSPARQL:\n"
    ),
)
 
 
def _cve_full(cid: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?description ?publishedDate ?cweName ?score WHERE {{
  ?cve cve:id "{cid}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve dct:issued ?publishedDate . }}
  OPTIONAL {{ ?cve cve:hasCWE ?cwe . OPTIONAL {{ ?cwe cwe:name ?cweName . }} }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
}} LIMIT 50"""
 
 
def _cve_cvss(cid: str) -> str:
    return f"""{PREFIXES}
SELECT ?score ?confImpact WHERE {{
  ?cve cve:id "{cid}" .
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m3 . ?m3 cvss:baseScore ?score ; cvss:confidentialityImpact ?confImpact . }}
  OPTIONAL {{ ?cve cve:hasCVSS2BaseMetric ?m2 . ?m2 cvss:baseScore ?score ; cvss:confidentialityImpact ?confImpact . }}
}} LIMIT 10"""
 
 
def _cve_capec(cid: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cweName ?capecName ?mitigation WHERE {{
  ?cve cve:id "{cid}" ; cve:hasCWE ?cwe .
  OPTIONAL {{ ?cwe cwe:name ?cweName . }}
  OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?capecName .
             OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }}
}} LIMIT 50"""
 
 
def _cves_by_cwe(cwe_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cveId WHERE {{ ?cwe cwe:id "{cwe_id}" . ?cve cve:hasCWE ?cwe ; cve:id ?cveId . }} LIMIT 30"""
 
 
def _high_severity_fallback() -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cveId ?score WHERE {{
  ?cve cve:id ?cveId ; cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score .
  FILTER(?score >= 9.0)
}} ORDER BY DESC(?score) LIMIT 10"""
 
 
def _regex_sparql(question: str) -> Optional[str]:
    q = question.lower()
    cve = CVE_RE.search(question)
    if cve:
        cid = cve.group().upper()
        if any(k in q for k in ("cvss", "score", "skor", "severity", "parah")):
            return _cve_cvss(cid)
        if any(k in q for k in ("capec", "attack pattern", "pola serangan", "mitigasi", "mitigation")):
            return _cve_capec(cid)
        return _cve_full(cid)
    cwe = CWE_RE.search(question)
    if cwe:
        return _cves_by_cwe(cwe.group().upper())
    return None
 
 
def _extract_sparql(text: str) -> str:
    m = re.search(r"```(?:sparql)?\s*([\s\S]+?)```", text, re.IGNORECASE)
    query = m.group(1).strip() if m else text.strip()
    if "PREFIX" not in query.upper():
        query = f"{PREFIXES}\n{query}"
    return query
 
 
def _valid_sparql(query: str) -> bool:
    if _FORBIDDEN.search(query):
        return False
    up = query.upper()
    return ("SELECT" in up or "ASK" in up) and "{" in query and "}" in query
 
 
def generate_sparql(question: str, model: str = DEFAULT_MODEL) -> Tuple[str, str]:
    """Kembalikan (query, method). method: regex | llm | fallback | fallback_keyword. Tidak pernah raise."""
    q = _regex_sparql(question)
    if q:
        return q, "regex"
    try:
        raw = (_PROMPT | LLMProvider.get_model(model)).invoke(
            {"ontology": ONTOLOGY_CONTEXT, "question": question}
        ).content
        q = _extract_sparql(raw)
        if _valid_sparql(q):
            return q, "llm"
    except Exception as e:
        print(f"[sparql] LLM nl2sparql gagal: {e}")
    cve = CVE_RE.search(question)
    if cve:
        return _cve_full(cve.group().upper()), "fallback"
    return _high_severity_fallback(), "fallback_keyword"