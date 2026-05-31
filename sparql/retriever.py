from __future__ import annotations

from typing import Dict, Any, List, Optional

from chatbot.api.sparql_client import (
    PREFIXES,
    bindings_to_rows,
    run_query,
    escape_sparql_literal,
)

# Default SEPSES Graph URIs
CAPEC_GRAPH = "http://sepses.ifs.tuwien.ac.at/data/capec"
CWE_GRAPH = "http://sepses.ifs.tuwien.ac.at/data/cwe"
SNORT_GRAPH = "http://sepses.ifs.tuwien.ac.at/data/snortrule"

# Generic Retrieval Helpers
def _run_select(query: str):
    """
    Execute SPARQL query and return simplified rows.
    """
    result = run_query(query)
    return bindings_to_rows(result)

def search_labels(
    keyword: str,
    *,
    graph_uri: Optional[str] = None,
    limit: int = 10,
) -> List[Dict[str, str]]:
    """
    Generic label search across a graph.
    """
    safe_keyword = escape_sparql_literal(keyword)

    if graph_uri:
        graph_clause = f"GRAPH <{graph_uri}>"
    else:
        graph_clause = ""

    query = f"""
{PREFIXES}

SELECT DISTINCT ?s ?label
WHERE {{
    {graph_clause} {{
        ?s rdfs:label ?label .

        FILTER(
            CONTAINS(
                LCASE(STR(?label)),
                LCASE("{safe_keyword}")
            )
        )
    }}
}}
LIMIT {int(limit)}
"""

    return _run_select(query)

# Vulnerability Retrieval
def retrieve_vulnerability(
    keyword: str,
    limit: int = 10,
):
    """
    Search vulnerabilities/CWE entries.
    """

    return search_labels(
        keyword,
        graph_uri=CWE_GRAPH,
        limit=limit,
    )

# Attack Pattern Retrieval
def retrieve_attack_pattern(
    keyword: str,
    limit: int = 10,
):
    """
    Search CAPEC attack patterns.
    """

    return search_labels(
        keyword,
        graph_uri=CAPEC_GRAPH,
        limit=limit,
    )

# Snort Rule Retrieval
def retrieve_snort_rule(
    keyword: str,
    limit: int = 10,
):
    """
    Search Snort rules.
    """

    return search_labels(
        keyword,
        graph_uri=SNORT_GRAPH,
        limit=limit,
    )

# Entity Relationship Exploration
def describe_entity(
    entity_uri: str,
    *,
    graph_uri: Optional[str] = None,
    limit: int = 50,
):
    """
    Retrieve outgoing/incoming relationships
    for an entity.
    """

    safe_uri = entity_uri.strip().strip("<>")

    if graph_uri:
        graph_clause = f"GRAPH <{graph_uri}>"
    else:
        graph_clause = ""

    query = f"""
{PREFIXES}

SELECT ?direction ?p ?o
WHERE {{

    {{
        BIND(<{safe_uri}> AS ?s)

        {graph_clause} {{
            ?s ?p ?o .
        }}

        BIND("outgoing" AS ?direction)
    }}

    UNION

    {{
        BIND(<{safe_uri}> AS ?o)

        {graph_clause} {{
            ?s ?p ?o .
        }}

        BIND("incoming" AS ?direction)
    }}

}}
LIMIT {int(limit)}
"""

    return _run_select(query)

# Graph Statistics
def get_graph_statistics(
    graph_uri: Optional[str] = None
):
    """
    Count triples in graph.
    """

    if graph_uri:
        graph_clause = f"GRAPH <{graph_uri}>"
    else:
        graph_clause = ""

    query = f"""
{PREFIXES}

SELECT (COUNT(*) AS ?triple_count)
WHERE {{
    {graph_clause} {{
        ?s ?p ?o .
    }}
}}
"""

    return _run_select(query)

# Entity Class Discovery
def list_entity_classes(
    graph_uri: Optional[str] = None,
    limit: int = 100,
):
    """
    Explore entity classes/types.
    """

    if graph_uri:
        graph_clause = f"GRAPH <{graph_uri}>"
    else:
        graph_clause = ""

    query = f"""
{PREFIXES}

SELECT ?class (COUNT(*) AS ?count)
WHERE {{
    {graph_clause} {{
        ?s rdf:type ?class .
    }}
}}
GROUP BY ?class
ORDER BY DESC(?count)
LIMIT {int(limit)}
"""

    return _run_select(query)

# Predicate Discovery
def list_predicates(
    graph_uri: Optional[str] = None,
    limit: int = 100,
):
    """
    Explore graph predicates/relationships.
    """

    if graph_uri:
        graph_clause = f"GRAPH <{graph_uri}>"
    else:
        graph_clause = ""

    query = f"""
{PREFIXES}

SELECT ?predicate (COUNT(*) AS ?count)
WHERE {{
    {graph_clause} {{
        ?s ?predicate ?o .
    }}
}}
GROUP BY ?predicate
ORDER BY DESC(?count)
LIMIT {int(limit)}
"""

    return _run_select(query)

# Context Builder for LLM
def build_llm_context(
    rows: List[Dict[str, str]],
    max_items: int = 10,
) -> str:
    """
    Convert KG retrieval results into
    compact context text for LLM prompting.
    """

    if not rows:
        return "No relevant cybersecurity knowledge found."

    lines = []

    for row in rows[:max_items]:

        row_text = []

        for key, value in row.items():
            row_text.append(f"{key}: {value}")

        lines.append(" | ".join(row_text))

    return "\n".join(lines)

# Quick Testing
if __name__ == "__main__":

    print("=" * 60)
    print("SEPSES KG Retriever Test")
    print("=" * 60)

    vulnerabilities = retrieve_vulnerability("overflow")

    print("\n[VULNERABILITY SEARCH]")
    for item in vulnerabilities:
        print(item)

    attack_patterns = retrieve_attack_pattern("phishing")

    print("\n[ATTACK PATTERN SEARCH]")
    for item in attack_patterns:
        print(item)

    stats = get_graph_statistics(CAPEC_GRAPH)

    print("\n[GRAPH STATS]")
    print(stats)