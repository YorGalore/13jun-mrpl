from __future__ import annotations
import json
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, List

from SPARQLWrapper import SPARQLWrapper, JSON, POST
from backend.config import(
    SPARQL_PUBLIC_ENDPOINT as DEFAULT_ENDPOINT,
    DEFAULT_GRAPH, SPARQL_TIMEOUT as DEFAULT_TIMEOUT
)
ssl._create_default_https_context = ssl._create_unverified_context

PREFIXES = """\
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX vuln: <http://w3id.org/sepses/vocab/vulnerability#>
PREFIX cpe: <http://w3id.org/sepses/vocab/ref/cpe#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
"""

class SPARQLClientError(RuntimeError):
    pass

def escape_sparql_literal(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )

def normalize_iri(iri: str) -> str:
    return iri.strip().strip("<>").replace(">", "")

@dataclass(frozen=True)
class SPARQLConfig:
    endpoint: str = DEFAULT_ENDPOINT
    timeout: int = DEFAULT_TIMEOUT
    default_graph: str = DEFAULT_GRAPH
    infer: bool = True

class VirtuosoClient:
    
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
        infer: Optional[bool] = None,
    ) -> Dict[str, Any]:
        
        wrapper = self._new_wrapper()
        target_graph = default_graph or self.config.default_graph
        if target_graph and target_graph.strip():
            wrapper.addDefaultGraph(target_graph.strip())
        if infer is None:
            infer = self.config.infer
        if infer:
            wrapper.addParameter("infer", "true")

        wrapper.setQuery(query_text)

        try:
            return wrapper.query().convert()
        except Exception as exc:  # pragma: no cover - endpoint/network failures
            raise SPARQLClientError(f"SPARQL query failed: {exc}") from exc

_client = VirtuosoClient()

def run_query(
    query_text: str,
    *,
    default_graph: Optional[str] = None,
    infer: bool = True,
) -> Dict[str, Any]:
    return _client.run_query(query_text, default_graph=default_graph, infer=infer)

def bindings_to_rows(result: Dict[str, Any]) -> List[Dict[str, str]]:

    rows: List[Dict[str, str]] = []
    for binding in result.get("results", {}).get("bindings", []):
        row = {key: value.get("value", "") for key, value in binding.items()}
        rows.append(row)
    return rows

def pretty_print_rows(rows: Iterable[Dict[str, str]]) -> str:
    return json.dumps(list(rows), indent=2, ensure_ascii=False)

def sparql_term(term: str) -> str:
    term = term.strip()
    if term.startswith("<") and term.endswith(">"):
        return term
    if term.startswith("http://") or term.startswith("https://"):
        return f"<{normalize_iri(term)}>"
    return term


def _graph_clause(graph_uri: Optional[str], triple_pattern: str) -> str:
    if graph_uri:
        return f"GRAPH <{normalize_iri(graph_uri)}> {{ {triple_pattern} }}"
    return triple_pattern


def list_named_graphs(limit: int = 100) -> Dict[str, Any]:
    query = f"""
    {PREFIXES}
    SELECT DISTINCT ?graph
    WHERE {{
        GRAPH ?graph {{ ?s ?p ?o . }}
    }}
    ORDER BY ?graph
    LIMIT {int(limit)}
    """
    return run_query(query, default_graph=None)

def count_triples(*, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    where_clause = _graph_clause(graph_uri, "?s ?p ?o .")
    query = f"""
    {PREFIXES}
    SELECT (COUNT(*) AS ?triple_count)
    WHERE {{
        {where_clause}
    }}
    """
    return run_query(query, default_graph=graph_uri)

def count_distinct_entities(*, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    query = f"""{PREFIXES}
    SELECT (COUNT(DISTINCT ?s) AS ?subjects) (COUNT(DISTINCT ?o) AS ?objects)
    WHERE {{ {_graph_clause(graph_uri, "?s ?p ?o .")} }}"""
    return run_query(query, default_graph=graph_uri)
count_entities = count_distinct_entities

def list_classes(*, graph_uri: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    where_clause = _graph_clause(graph_uri, "?s rdf:type ?class .")
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
    where_clause = _graph_clause(graph_uri, "?s ?predicate ?o .")
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
    where_clause = _graph_clause(graph_uri, "?s ?p ?o .")
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
    where_clause = _graph_clause(
        graph_uri,
        f"""
        ?s rdfs:label ?label .
        FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{safe_keyword}")))
        """,
    )
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


def count_instances_of(class_term: str, *, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    class_ref = sparql_term(class_term)
    where_clause = _graph_clause(graph_uri, f"?entity a {class_ref} .")
    query = f"""
    {PREFIXES}
    SELECT (COUNT(*) AS ?count)
    WHERE {{
        {where_clause}
    }}
    """
    return run_query(query, default_graph=graph_uri)

def sample_instances_of(
    class_term: str,
    *,
    graph_uri: Optional[str] = None,
    limit: int = 5,
) -> Dict[str, Any]:
    class_ref = sparql_term(class_term)
    where_clause = _graph_clause(
        graph_uri,
        f"""
        ?entity a {class_ref} .
        OPTIONAL {{ ?entity rdfs:label ?label . }}
        """,
    )
    query = f"""
    {PREFIXES}
    SELECT DISTINCT ?entity ?label
    WHERE {{
        {where_clause}
    }}
    ORDER BY LCASE(STR(COALESCE(?label, STR(?entity))))
    LIMIT {int(limit)}
    """
    return run_query(query, default_graph=graph_uri)

def count_predicate_usage(predicate_term: str, *, graph_uri: Optional[str] = None) -> Dict[str, Any]:
    predicate_ref = sparql_term(predicate_term)
    where_clause = _graph_clause(graph_uri, f"?s {predicate_ref} ?o .")
    query = f"""
    {PREFIXES}
    SELECT (COUNT(*) AS ?count)
    WHERE {{
        {where_clause}
    }}
    """
    return run_query(query, default_graph=graph_uri)

def describe_entity_neighbors(entity_iri: str, *, graph_uri: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
    safe = normalize_iri(entity_iri)
    out = _graph_clause(graph_uri, "?entity ?predicate ?neighbor . OPTIONAL { ?predicate rdfs:label ?predicateLabel . }")
    inc = _graph_clause(graph_uri, "?neighbor ?predicate ?entity . OPTIONAL { ?predicate rdfs:label ?predicateLabel . }")
    query = f"""{PREFIXES}
    SELECT ?direction ?neighbor ?predicate ?predicateLabel WHERE {{
      {{ BIND("outgoing" AS ?direction) BIND(<{safe}> AS ?entity) {out} }}
      UNION
      {{ BIND("incoming" AS ?direction) BIND(<{safe}> AS ?entity) {inc} }}
    }} LIMIT {int(limit)}"""
    return run_query(query, default_graph=graph_uri)


if __name__ == "__main__":
    q = f"""{PREFIXES}
SELECT ?cveId WHERE {{ ?cve cve:id ?cveId . }} LIMIT 5"""
    print(pretty_print_rows(bindings_to_rows(run_query(q))))