from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple
from langchain_core.prompts import PromptTemplate

from backend.config import SPARQL_PUBLIC_ENDPOINT, SPARQL_TIMEOUT
from backend.llm.llm_models import LLMProvider, DEFAULT_MODEL
from backend.patterns import CVE_RE
from backend.sparql.client import PREFIXES, SPARQLConfig, VirtuosoClient, bindings_to_rows
from backend.sparql.ontology_context import (ONTOLOGY_CONTEXT)

# Operasi tulis yang dilarang (read-only guard).
_FORBIDDEN = re.compile(
    r"\b(INSERT|DELETE|DROP|CLEAR|LOAD|CREATE|COPY|MOVE|ADD)\b", re.IGNORECASE
)

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_CAPEC_RE = re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE)

template = """
You are a cybersecurity SPARQL expert.

- Translate the user question into valid SPARQL.
- Use the ontology below. Use OPTIONAL for properties that may be missing.
- Always include PREFIX declarations. Return ONLY SPARQL query.

Ontology:
{ontology}

Question:
{question}

SPARQL:
"""

prompt = PromptTemplate(
    input_variables=["ontology", "question"],
    template=template
)

def _cve_full(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?description ?publishedDate ?cweName ?score WHERE {{
  ?cve cve:id "{cve_id}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve cve:publishedDate ?publishedDate . }}
  OPTIONAL {{ ?cve cve:hasCWE ?cwe . ?cwe cwe:name ?cweName . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
}} LIMIT 50"""


def _cve_cvss(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT ?score ?confImpact WHERE {{
  ?cve cve:id "{cve_id}" .
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m3 . ?m3 cvss:baseScore ?score ;
                 cvss:confidentialityImpact ?confImpact . }}
  OPTIONAL {{ ?cve cve:hasCVSS2BaseMetric ?m2 . ?m2 cvss:baseScore ?score ;
                 cvss:confidentialityImpact ?confImpact . }}
}} LIMIT 10"""


def _cve_capec(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cweName ?capecName ?mitigation WHERE {{
  ?cve cve:id "{cve_id}" ; cve:hasCWE ?cwe .
  OPTIONAL {{ ?cwe cwe:name ?cweName . }}
  OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?capecName .
             OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }}
}} LIMIT 50"""


def _cve_products(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cpe WHERE {{
  ?cve cve:id "{cve_id}" ; cve:hasCPE ?cpe .
}} LIMIT 30"""


def _cves_by_cwe(cwe_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cveId WHERE {{
  ?cwe cwe:id "{cwe_id}" .
  ?cve cve:hasCWE ?cwe ; cve:id ?cveId .
}} LIMIT 30"""


def regex_sparql(question: str) -> Optional[str]:
    """Fast-path tanpa LLM. None bila tak ada pola dikenal."""
    q = question.lower()

    cve = CVE_RE.search(question)
    if cve:
        cid = cve.group().upper()
        if any(k in q for k in ("cvss", "score", "skor", "severity", "parah")):
            return _cve_cvss(cid)
        if any(k in q for k in ("capec", "attack pattern", "pola serangan", "mitigasi", "mitigation")):
            return _cve_capec(cid)
        if any(k in q for k in ("produk", "product", "cpe", "software", "terdampak", "affected")):
            return _cve_products(cid)
        return _cve_full(cid)

    cwe = _CWE_RE.search(question)
    if cwe:
        return _cves_by_cwe(cwe.group().upper())

    return None
    

# LLM Generator
def llm_generate(question: str, model: str = DEFAULT_MODEL) -> str:
    llm = LLMProvider.get_model(model)
    chain = prompt | llm
    response = chain.invoke({"ontology": ONTOLOGY_CONTEXT, "question": question})
    return response.content.strip()


def extract_sparql(text: str) -> str:
    match = re.search(r"```(?:sparql)?\s*([\s\S]+?)```", text, re.IGNORECASE)
    query = match.group(1).strip() if match else text.strip()
    # Pastikan prefix tersedia agar query tidak gagal saat dieksekusi.
    if "PREFIX" not in query.upper():
        query = f"{PREFIXES}\n{query}"
    return query


def validate_sparql(query: str) -> bool:
    upper = query.upper()
    if _FORBIDDEN.search(query):
        return False
    has_select = "SELECT" in upper or "ASK" in upper
    return has_select and "{" in query and "}" in query


def generate_sparql(question: str, model: str = DEFAULT_MODEL) -> Tuple[str, str]:
    """Kembalikan (query, method). method = 'regex' | 'llm' | 'fallback'.
    TIDAK PERNAH raise: selalu mengembalikan query yang bisa dieksekusi."""
    q = regex_sparql(question)
    if q:
        return q, "regex"

    try:
        raw = llm_generate(question, model=model)
        q = extract_sparql(raw)
        if validate_sparql(q):
            return q, "llm"
    except Exception:
        pass  # turun ke fallback

    # Fallback aman: kalau ada CVE -> detail penuh; kalau tidak -> CVE skor tinggi.
    cve = CVE_RE.search(question)
    if cve:
        return _cve_full(cve.group().upper()), "fallback"
    return (f"""{PREFIXES}
            SELECT DISTINCT ?cveId ?score WHERE {{
            ?cve cve:id ?cveId ; cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score .
            FILTER(?score >= 9.0)
            }} ORDER BY DESC(?score) LIMIT 10""",
        "fallback",
    )

def run_kg_query(query: str) -> List[Dict[str, str]]:
    """Eksekusi pada endpoint publik (jalur utama).
    SPARQLConfig sekarang public-safe (default_graph=None, infer=False) sehingga
    query tidak lagi dipaksa ke graph kosong. Bila publik gagal, client otomatis
    mencoba Virtuoso lokal (lihat backend/sparql/client.run_query)."""

    client = VirtuosoClient(SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT, timeout=SPARQL_TIMEOUT))
    return bindings_to_rows(client.run_query(query))


def execute_question(question: str, model: str = DEFAULT_MODEL) -> dict:
    sparql_query, method = generate_sparql(question, model=model)
    rows = run_kg_query(sparql_query)
    return {"question": question, "method": method, "sparql": sparql_query, "results": rows}
execute_nl_query = execute_question

# Demo
if __name__ == "__main__":
    q = "Show vulnerabilities related to CVE-2021-44228"

    result = execute_question(q)
    print("QUESTION:")
    print(result["question"])
    print("METHOD  :")
    print(result["method"])
    print("\nSPARQL:")
    print(result["sparql"])
    print("\nRESULTS:")
    for r in result["results"]:
        print(r)

        