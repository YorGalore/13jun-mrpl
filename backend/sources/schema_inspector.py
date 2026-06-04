from __future__ import annotations

import argparse
import json
import ssl
import sys
from pathlib import Path
from typing import Dict, List, Optional

from SPARQLWrapper import JSON, POST, SPARQLWrapper

from backend.config import (
    ROOT,
    SPARQL_LOCAL_ENDPOINT,
    SPARQL_LOCAL_GRAPH,
    SPARQL_PUBLIC_ENDPOINT,
    SPARQL_TIMEOUT,
)

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

CURATED_CLASSES = [
    ("cve:CVE", "CVE", "http://w3id.org/sepses/vocab/ref/cve#CVE"),
    ("cwe:Weakness", "CWE Weakness", "http://w3id.org/sepses/vocab/ref/cwe#Weakness"),
    ("capec:AttackPattern", "CAPEC Attack Pattern", "http://w3id.org/sepses/vocab/ref/capec#AttackPattern"),
    ("cpe:CPE", "CPE Platform", "http://w3id.org/sepses/vocab/ref/cpe#CPE"),
    ("cvss:CVSS3", "CVSS v3 Metric", "http://w3id.org/sepses/vocab/ref/cvss#CVSS3"),
]

CURATED_RELATIONS = [
    ("cve:hasCWE", "CVE -> CWE", "http://w3id.org/sepses/vocab/ref/cve#hasCWE"),
    ("cve:hasCPE", "CVE -> CPE", "http://w3id.org/sepses/vocab/ref/cve#hasCPE"),
    ("cve:hasCVSS3BaseMetric", "CVE -> CVSS3", "http://w3id.org/sepses/vocab/ref/cve#hasCVSS3BaseMetric"),
    ("cwe:hasCAPEC", "CWE -> CAPEC", "http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC"),
    ("cvss:baseScore", "CVSS -> baseScore", "http://w3id.org/sepses/vocab/ref/cvss#baseScore"),
]


def _run(endpoint: str, query: str, graph: Optional[str]) -> List[Dict[str, str]]:
    """Eksekusi satu query; kembalikan [] (tidak raise) bila gagal."""
    try:
        w = SPARQLWrapper(endpoint)
        w.setReturnFormat(JSON)
        w.setMethod(POST)
        w.setTimeout(SPARQL_TIMEOUT)
        if graph:
            w.addDefaultGraph(graph)
        w.setQuery(query)
        result = w.query().convert()
        bindings = result.get("results", {}).get("bindings", [])
        return [{k: v.get("value", "") for k, v in row.items()} for row in bindings]
    except Exception as e:
        print(f"[schema] query gagal: {str(e)[:160]}")
        return []


def _scalar(rows: List[Dict[str, str]], key: str) -> str:
    return rows[0].get(key, "") if rows else ""


def inspect(endpoint: str, graph: Optional[str]) -> Dict:
    print(f"[schema] inspeksi endpoint={endpoint} graph={graph or '(default)'}")

    triple_rows = _run(endpoint, f"{PREFIXES}\nSELECT (COUNT(*) AS ?c) WHERE {{ ?s ?p ?o }}", graph)
    ent_rows = _run(
        endpoint,
        f"{PREFIXES}\nSELECT (COUNT(DISTINCT ?s) AS ?subjects) (COUNT(DISTINCT ?o) AS ?objects) WHERE {{ ?s ?p ?o }}",
        graph,
    )
    top_classes = _run(
        endpoint,
        f"{PREFIXES}\nSELECT ?type (COUNT(?s) AS ?count) WHERE {{ ?s a ?type }} GROUP BY ?type ORDER BY DESC(?count) LIMIT 20",
        graph,
    )
    top_predicates = _run(
        endpoint,
        f"{PREFIXES}\nSELECT ?p (COUNT(*) AS ?count) WHERE {{ ?s ?p ?o }} GROUP BY ?p ORDER BY DESC(?count) LIMIT 20",
        graph,
    )
    sample_triples = _run(endpoint, f"{PREFIXES}\nSELECT ?s ?p ?o WHERE {{ ?s ?p ?o }} LIMIT 25", graph)

    curated_classes = []
    for short, label, uri in CURATED_CLASSES:
        rows = _run(endpoint, f"{PREFIXES}\nSELECT (COUNT(?s) AS ?count) WHERE {{ ?s a <{uri}> }}", graph)
        curated_classes.append({"class": short, "label": label, "uri": uri, "count": _scalar(rows, "count") or "0"})

    curated_relations = []
    for short, label, uri in CURATED_RELATIONS:
        rows = _run(endpoint, f"{PREFIXES}\nSELECT (COUNT(*) AS ?count) WHERE {{ ?s <{uri}> ?o }}", graph)
        curated_relations.append({"predicate": short, "label": label, "uri": uri, "count": _scalar(rows, "count") or "0"})

    return {
        "endpoint": endpoint,
        "graph": graph or "(default graph)",
        "triple_count": _scalar(triple_rows, "c") or "0",
        "distinct_subjects": _scalar(ent_rows, "subjects") or "0",
        "distinct_objects": _scalar(ent_rows, "objects") or "0",
        "top_classes": top_classes,
        "top_predicates": top_predicates,
        "curated_classes": curated_classes,
        "curated_relations": curated_relations,
        "sample_triples": sample_triples,
    }


def _md(report: Dict) -> str:
    lines = [
        "# SEPSES CSKG Schema Report",
        "",
        f"- Endpoint: `{report['endpoint']}`",
        f"- Graph: `{report['graph']}`",
        f"- Triples: `{report['triple_count']}`",
        f"- Distinct subjects: `{report['distinct_subjects']}`",
        f"- Distinct objects: `{report['distinct_objects']}`",
        "",
        "## Top Classes",
        "",
    ]
    if report["top_classes"]:
        lines += ["| class | count |", "| --- | --- |"]
        lines += [f"| {r.get('type', '')} | {r.get('count', '')} |" for r in report["top_classes"]]
    else:
        lines.append("_No data found (endpoint kosong / tidak tersedia)._")

    lines += ["", "## Top Predicates", ""]
    if report["top_predicates"]:
        lines += ["| predicate | count |", "| --- | --- |"]
        lines += [f"| {r.get('p', '')} | {r.get('count', '')} |" for r in report["top_predicates"]]
    else:
        lines.append("_No data found._")

    lines += ["", "## Curated Security Classes", "", "| class | label | count |", "| --- | --- | --- |"]
    lines += [f"| {c['class']} | {c['label']} | {c['count']} |" for c in report["curated_classes"]]

    lines += ["", "## Curated Security Relations", "", "| predicate | label | count |", "| --- | --- | --- |"]
    lines += [f"| {r['predicate']} | {r['label']} | {r['count']} |" for r in report["curated_relations"]]

    lines += ["", "## Sample Triples", ""]
    if report["sample_triples"]:
        lines += ["| subject | predicate | object |", "| --- | --- | --- |"]
        for r in report["sample_triples"]:
            s = (r.get("s", "") or "")[:80]
            p = (r.get("p", "") or "")[:80]
            o = (r.get("o", "") or "")[:80]
            lines.append(f"| {s} | {p} | {o} |")
    else:
        lines.append("_No data found._")

    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SEPSES CSKG schema report.")
    parser.add_argument("--target", choices=["local", "public"], default="local",
                        help="local = Virtuoso lokal (default), public = endpoint SEPSES publik.")
    parser.add_argument("--endpoint", default=None, help="Override URL endpoint SPARQL.")
    parser.add_argument("--graph", default=None, help="Override named graph (kosongkan untuk default graph).")
    parser.add_argument("--out", default=str(ROOT / "docs"), help="Direktori output dokumen.")
    args = parser.parse_args(argv)

    if args.endpoint:
        endpoint = args.endpoint
        graph = args.graph
    elif args.target == "public":
        endpoint = SPARQL_PUBLIC_ENDPOINT
        graph = args.graph  # publik: default graph (None) kecuali di-override
    else:
        endpoint = SPARQL_LOCAL_ENDPOINT
        graph = args.graph or SPARQL_LOCAL_GRAPH

    report = inspect(endpoint, graph)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "knowledge_graph_schema.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "knowledge_graph_schema.md").write_text(_md(report), encoding="utf-8")

    print(f"[schema] Triples={report['triple_count']} "
          f"subjects={report['distinct_subjects']} objects={report['distinct_objects']}")
    print(f"[schema] Ditulis ke {out_dir}/knowledge_graph_schema.(json|md)")
    if report["triple_count"] in ("", "0"):
        print("[schema] CATATAN: 0 triple. Jika target lokal, pastikan Virtuoso jalan & data "
              "sudah dimuat (docker compose up / bash scripts/load_virtuoso.sh).")
    return 0


if __name__ == "__main__":
    sys.exit(main())