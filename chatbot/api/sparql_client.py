from __future__ import annotations

import os
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, List

from SPARQLWrapper import SPARQLWrapper, JSON, POST


DEFAULT_ENDPOINT = os.getenv(
    "SEPSES_SPARQL_ENDPOINT",
    "http://localhost:8890/sparql",
)
DEFAULT_TIMEOUT = int(os.getenv("SEPSES_SPARQL_TIMEOUT", "60"))


PREFIXES = """\
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:  <http://www.w3.org/2002/07/owl#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>
"""


class SPARQLClientError(RuntimeError):
    """Raised when a SPARQL query fails."""


def escape_sparql_literal(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


@dataclass(frozen=True)
class SPARQLConfig:
    endpoint: str = DEFAULT_ENDPOINT
    timeout: int = DEFAULT_TIMEOUT


class VirtuosoClient:
    """
    Lightweight reusable client for Virtuoso SPARQL endpoint.
    A fresh SPARQLWrapper instance is created per query to avoid state leakage.
    """

    def __init__(self, config: Optional[SPARQLConfig] = None):
        self.config = config or SPARQLConfig()

    def _new_wrapper(self) -> SPARQLWrapper:
        wrapper = SPARQLWrapper(self.config.endpoint)
        wrapper.setReturnFormat(JSON)
        wrapper.setMethod(POST)
        wrapper.setTimeout(self.config.timeout)
        return wrapper

    def run_query(
        self,
        query_text: str,
        *,
        default_graph: Optional[str] = None,
        infer: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a SELECT/ASK query and return parsed JSON.
        """
        wrapper = self._new_wrapper()

        if default_graph:
            wrapper.addDefaultGraph(default_graph)

        if infer:
            wrapper.addParameter("infer", "true")

        wrapper.setQuery(query_text)

        try:
            return wrapper.query().convert()
        except Exception as exc:  # pragma: no cover - endpoint/network failures
            raise SPARQLClientError(f"SPARQL query failed: {exc}") from exc


_client = VirtuosoClient()


def run_query(query_text: str, *, default_graph: Optional[str] = None) -> Dict[str, Any]:
    """Public helper used by other modules."""
    return _client.run_query(query_text, default_graph=default_graph)


def bindings_to_rows(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert SPARQL JSON bindings into simple row dictionaries."""
    rows: List[Dict[str, str]] = []
    for binding in result.get("results", {}).get("bindings", []):
        row = {key: value.get("value", "") for key, value in binding.items()}
        rows.append(row)
    return rows


def pretty_print_rows(rows: Iterable[Dict[str, str]]) -> str:
    return json.dumps(list(rows), indent=2, ensure_ascii=False)


def list_graphs(limit: int = 100) -> Dict[str, Any]:
    query = f"""
{PREFIXES}
SELECT DISTINCT ?graph
WHERE {{
    GRAPH ?graph {{
        ?s ?p ?o .
    }}
}}
ORDER BY ?graph
LIMIT {int(limit)}
"""
    return run_query(query)


def count_triples(*, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    if graph_uri:
        where_clause = f"GRAPH <{graph_uri}> {{ ?s ?p ?o . }}"
    else:
        where_clause = "?s ?p ?o ."

    query = f"""
{PREFIXES}
SELECT (COUNT(*) AS ?triple_count)
WHERE {{
    {where_clause}
}}
"""
    return run_query(query, default_graph=graph_uri)


def list_classes(*, graph_uri: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    if graph_uri:
        where_clause = f"GRAPH <{graph_uri}> {{ ?s rdf:type ?class . }}"
    else:
        where_clause = "?s rdf:type ?class ."

    query = f"""
{PREFIXES}
SELECT ?class (COUNT(*) AS ?count)
WHERE {{
    {where_clause}
}}
GROUP BY ?class
ORDER BY DESC(?count)
LIMIT {int(limit)}
"""
    return run_query(query, default_graph=graph_uri)


def list_predicates(*, graph_uri: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    if graph_uri:
        where_clause = f"GRAPH <{graph_uri}> {{ ?s ?predicate ?o . }}"
    else:
        where_clause = "?s ?predicate ?o ."

    query = f"""
{PREFIXES}
SELECT ?predicate (COUNT(*) AS ?count)
WHERE {{
    {where_clause}
}}
GROUP BY ?predicate
ORDER BY DESC(?count)
LIMIT {int(limit)}
"""
    return run_query(query, default_graph=graph_uri)


def sample_triples(*, graph_uri: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    if graph_uri:
        where_clause = f"GRAPH <{graph_uri}> {{ ?s ?p ?o . }}"
    else:
        where_clause = "?s ?p ?o ."

    query = f"""
{PREFIXES}
SELECT ?s ?p ?o
WHERE {{
    {where_clause}
}}
LIMIT {int(limit)}
"""
    return run_query(query, default_graph=graph_uri)


def search_labels(
    keyword: str,
    *,
    graph_uri: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    safe_keyword = escape_sparql_literal(keyword)

    if graph_uri:
        where_clause = f"""
GRAPH <{graph_uri}> {{
    ?s rdfs:label ?label .
    FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{safe_keyword}")))
}}
"""
    else:
        where_clause = f"""
?s rdfs:label ?label .
FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{safe_keyword}")))
"""

    query = f"""
{PREFIXES}
SELECT DISTINCT ?s ?label
WHERE {{
    {where_clause}
}}
ORDER BY LCASE(STR(?label))
LIMIT {int(limit)}
"""
    return run_query(query, default_graph=graph_uri)


def describe_entity(entity_iri: str, *, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    safe_iri = entity_iri.strip().strip("<>").replace(">", "")

    if graph_uri:
        query_body = f"""
    {{
        BIND(<{safe_iri}> AS ?s)
        GRAPH <{graph_uri}> {{
            ?s ?p ?o .
        }}
        BIND("outgoing" AS ?direction)
    }}
    UNION
    {{
        BIND(<{safe_iri}> AS ?o)
        GRAPH <{graph_uri}> {{
            ?s ?p ?o .
        }}
        BIND("incoming" AS ?direction)
    }}
"""
    else:
        query_body = f"""
    {{
        BIND(<{safe_iri}> AS ?s)
        ?s ?p ?o .
        BIND("outgoing" AS ?direction)
    }}
    UNION
    {{
        BIND(<{safe_iri}> AS ?o)
        ?s ?p ?o .
        BIND("incoming" AS ?direction)
    }}
"""

    query = f"""
{PREFIXES}
SELECT ?p ?o ?direction
WHERE {{
{query_body}
}}
LIMIT 200
"""
    return run_query(query, default_graph=graph_uri)


if __name__ == "__main__":
    result = sample_triples(graph_uri="http://sepses.ifs.tuwien.ac.at/data/capec", limit=10)
    rows = bindings_to_rows(result)
    print(pretty_print_rows(rows))