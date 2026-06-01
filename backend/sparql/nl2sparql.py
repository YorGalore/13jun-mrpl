from __future__ import annotations
import re
from typing import Any, Dict, List, Tuple
from langchain.prompts import PromptTemplate

from backend.config import DEFAULT_GRAPH, SPARQL_ENDPOINT, SPARQL_PUBLIC_ENDPOINT, SPARQL_TIMEOUT
from backend.llm.llm_models import LLMProvider, DEFAULT_MODEL
from backend.sparql.client import SPARQLConfig, VirtuosoClient, bindings_to_rows
from backend.sparql.ontology_context import (ONTOLOGY_CONTEXT)

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Operasi tulis yang dilarang (read-only guard).
_FORBIDDEN = re.compile(
    r"\b(INSERT|DELETE|DROP|CLEAR|LOAD|CREATE|COPY|MOVE|ADD)\b", re.IGNORECASE
)

template = """
You are a cybersecurity SPARQL expert.

- Translate the user question into valid SPARQL.
- Use the ontology below.
- Return ONLY SPARQL query.

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

def pick_endpoint(query: str) -> Tuple[str, str | None, bool]:
    q = query.lower()
    if "cve:" in q or "cvss:" in q or CVE_RE.search(query):
        return SPARQL_PUBLIC_ENDPOINT, None, False
    return SPARQL_ENDPOINT, DEFAULT_GRAPH, True

# Simple Regex Fast Path
def regex_sparql(question: str):
    
    # Cari CVE ID
    cve_match = re.search(r"(CVE-\d{4}-\d+)", question, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(1).upper()
        return f"""
PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>

SELECT ?description
WHERE {{
    ?cve cve:id "{cve_id}" ;
         cve:description ?description .
}}
LIMIT 50
"""
    

# LLM Generator
def llm_generate(question: str, model: str = DEFAULT_MODEL) -> str:
    llm = LLMProvider.get_model(model)
    chain = prompt | llm
    response = chain.invoke({"ontology": ONTOLOGY_CONTEXT, "question": question})
    return response.content.strip()


def extract_sparql(text: str) -> str:
    """Ambil isi blok ```sparql ... ``` bila ada, kalau tidak kembalikan apa adanya."""
    match = re.search(r"```(?:sparql)?\s*([\s\S]+?)```", text, re.IGNORECASE)
    return match.group(1).strip() if match else text.strip()


def validate_sparql(query: str) -> bool:
    upper = query.upper()
    if _FORBIDDEN.search(query):
        return False
    has_select = "SELECT" in upper or "ASK" in upper
    return has_select and "{" in query and "}" in query


def generate_sparql(question: str, model: str = DEFAULT_MODEL) -> Tuple[str, str]:
    """Kembalikan (query, method) dengan method 'regex' atau 'llm'."""
    query = regex_sparql(question)
    if query:
        return query, "regex"

    raw_output = llm_generate(question, model=model)
    query = extract_sparql(raw_output)
    if not validate_sparql(query):
        raise ValueError("SPARQL hasil LLM tidak valid / bukan read-only.")
    return query, "llm"

def run_kg_query(query: str) -> List[Dict[str, str]]:
    """Eksekusi query pada endpoint yang sesuai isinya, kembalikan baris sederhana."""
    endpoint, graph, infer = pick_endpoint(query)
    client = VirtuosoClient(SPARQLConfig(
        endpoint=endpoint, default_graph=graph, infer=infer, timeout=SPARQL_TIMEOUT))
    raw = client.run_query(query, default_graph=graph, infer=infer)
    return bindings_to_rows(raw)

# Execute Query
def execute_question(question: str):
    sparql_query, method = generate_sparql(question)
    raw_result = run_query(sparql_query)

    rows = bindings_to_rows(raw_result)

    return {
        "question": question,
        "method": method,
        "sparql": sparql_query,
        "results": rows
    }

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

        