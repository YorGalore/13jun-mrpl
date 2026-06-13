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

# Endpoint SEPSES kadang memakai sertifikat rewel; lewati verifikasi SSL.
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

# Kelas & relasi keamanan yang ingin kita dokumentasikan secara eksplisit.
# CATATAN: nama kelas diverifikasi dari dump SEPSES nyata (rdf:type) + RML generator
# (sepses/cyber-kg-converter). CVE=cve:CVE, CWE=cwe:CWE, CAPEC=capec:CAPEC, CPE=cpe:CPE.
CURATED_CLASSES = [
    ("cve:CVE", "CVE Vulnerability", "http://w3id.org/sepses/vocab/ref/cve#CVE"),
    ("cwe:CWE", "CWE Weakness", "http://w3id.org/sepses/vocab/ref/cwe#CWE"),
    ("capec:CAPEC", "CAPEC Attack Pattern", "http://w3id.org/sepses/vocab/ref/capec#CAPEC"),
    ("cpe:CPE", "CPE Platform", "http://w3id.org/sepses/vocab/ref/cpe#CPE"),
    ("cvss:CVSS3BaseMetric", "CVSS v3 Base Metric", "http://w3id.org/sepses/vocab/ref/cvss#CVSS3BaseMetric"),
    ("cvss:CVSS2BaseMetric", "CVSS v2 Base Metric", "http://w3id.org/sepses/vocab/ref/cvss#CVSS2BaseMetric"),
]

# Object properties (relasi antar-entitas). Diverifikasi dari dump/RML SEPSES.
CURATED_RELATIONS = [
    ("cve:hasCWE", "CVE -> CWE", "http://w3id.org/sepses/vocab/ref/cve#hasCWE"),
    ("cve:hasCPE", "CVE -> CPE", "http://w3id.org/sepses/vocab/ref/cve#hasCPE"),
    ("cve:hasVulnerableConfiguration", "CVE -> VulnConfig (CPE)", "http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration"),
    ("cve:hasCVSS3BaseMetric", "CVE -> CVSS3", "http://w3id.org/sepses/vocab/ref/cve#hasCVSS3BaseMetric"),
    ("cve:hasCVSS2BaseMetric", "CVE -> CVSS2", "http://w3id.org/sepses/vocab/ref/cve#hasCVSS2BaseMetric"),
    ("cwe:hasCAPEC", "CWE -> CAPEC", "http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC"),
    ("cwe:hasCommonConsequence", "CWE -> Consequence (node)", "http://w3id.org/sepses/vocab/ref/cwe#hasCommonConsequence"),
    ("cwe:hasPotentialMitigation", "CWE -> Mitigation (node)", "http://w3id.org/sepses/vocab/ref/cwe#hasPotentialMitigation"),
]

# Datatype properties (atribut bernilai literal). Diverifikasi dari dump nyata
# (data/cskg_dumps) + RML generator. Untuk poin yang sempat ambigu (id/description CVE)
# SENGAJA dimasukkan dua kandidat sekaligus, agar laporan count mengungkap mana yang
# benar-benar terisi di endpoint live.
CURATED_DATATYPE_PROPS = [
    # --- CVE: identifier & description (dua kandidat agar terbukti dari count) ---
    ("dct:identifier", "CVE id via Dublin Core (generator JSON SEPSES terkini)", "http://purl.org/dc/terms/identifier"),
    ("cve:id", "CVE id via vocab cve (generator XML lama; cek apakah masih terisi)", "http://w3id.org/sepses/vocab/ref/cve#id"),
    ("dct:description", "Deskripsi (Dublin Core) — dipakai CVE, CWE, & CAPEC", "http://purl.org/dc/terms/description"),
    ("cve:description", "Deskripsi via vocab cve (generator XML lama; cek count)", "http://w3id.org/sepses/vocab/ref/cve#description"),
    ("dct:issued", "Tanggal terbit CVE (Dublin Core)", "http://purl.org/dc/terms/issued"),
    ("dct:modified", "Tanggal ubah CVE (Dublin Core)", "http://purl.org/dc/terms/modified"),
    # --- CWE ---
    ("cwe:id", "CWE id (literal)", "http://w3id.org/sepses/vocab/ref/cwe#id"),
    ("cwe:name", "CWE name", "http://w3id.org/sepses/vocab/ref/cwe#name"),
    ("cwe:consequenceImpact", "Dampak konsekuensi CWE (pada node Consequence)", "http://w3id.org/sepses/vocab/ref/cwe#consequenceImpact"),
    ("cwe:mitigationDescription", "Teks mitigasi CWE (pada node PotentialMitigation)", "http://w3id.org/sepses/vocab/ref/cwe#mitigationDescription"),
    # --- CAPEC ---
    ("capec:id", "CAPEC id (literal)", "http://w3id.org/sepses/vocab/ref/capec#id"),
    ("capec:name", "CAPEC name", "http://w3id.org/sepses/vocab/ref/capec#name"),
    ("capec:hasMitigation", "Mitigasi CAPEC (LITERAL langsung, bukan node)", "http://w3id.org/sepses/vocab/ref/capec#hasMitigation"),
    ("capec:likelihoodOfAttack", "Likelihood of attack CAPEC", "http://w3id.org/sepses/vocab/ref/capec#likelihoodOfAttack"),
    # --- CVSS ---
    ("cvss:baseScore", "CVSS base score (pada node metric)", "http://w3id.org/sepses/vocab/ref/cvss#baseScore"),
    ("cvss:confidentialityImpact", "CVSS confidentiality impact", "http://w3id.org/sepses/vocab/ref/cvss#confidentialityImpact"),
    ("cvss:attackVector", "CVSS attack vector", "http://w3id.org/sepses/vocab/ref/cvss#attackVector"),
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
 
    curated_datatype_props = []
    for short, label, uri in CURATED_DATATYPE_PROPS:
        rows = _run(endpoint, f"{PREFIXES}\nSELECT (COUNT(*) AS ?count) WHERE {{ ?s <{uri}> ?o }}", graph)
        curated_datatype_props.append({"property": short, "label": label, "uri": uri, "count": _scalar(rows, "count") or "0"})
 
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
        "curated_datatype_props": curated_datatype_props,
        "sample_triples": sample_triples,
    }


_VERIFIED_NOTES = """\
## Verified Schema (Issue #1)

Diverifikasi terhadap dump SEPSES nyata (`data/cskg_dumps/*.ttl`) dan generator
resmi `sepses/cyber-kg-converter` (`rml/cve-json.rml`, `config.properties`).
Kolom `count` di bawah diisi otomatis saat skrip dijalankan ke data nyata; angka 0
pada salah satu kandidat (mis. `cve:id` vs `dct:identifier`) menandakan predikat
itu TIDAK dipakai di endpoint tersebut.

**Pola IRI sumber daya (entry-point yang andal, lepas dari predikat id):**
- CVE   : `http://w3id.org/sepses/resource/cve/CVE-YYYY-NNNN`
- CWE   : `http://w3id.org/sepses/resource/cwe/CWE-N`
- CAPEC : `http://w3id.org/sepses/resource/capec/CAPEC-N`

**Temuan kunci:**
- Deskripsi CVE/CWE/CAPEC memakai **`dct:description`** (Dublin Core), bukan
  `cve:description`/`cwe:description`/`capec:description`.
- Id CVE dari generator JSON terkini memakai **`dct:identifier`** (id juga selalu
  ada di IRI). Karena itu lookup CVE sebaiknya mengikat lewat IRI, bukan `cve:id`.
- Mitigasi CAPEC = **`capec:hasMitigation`** berisi **literal langsung**
  (bukan `capec:mitigation`, bukan node).
- Mitigasi CWE = node via `cwe:hasPotentialMitigation` -> teks di
  `cwe:mitigationDescription`.
- Nama kelas yang benar: `cve:CVE`, `cwe:CWE`, `capec:CAPEC`, `cpe:CPE`
  (bukan `cwe:Weakness` / `capec:AttackPattern`).
"""


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
        _VERIFIED_NOTES,
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
 
    lines += ["", "## Curated Datatype Properties", "", "| property | label | count |", "| --- | --- | --- |"]
    lines += [f"| {p['property']} | {p['label']} | {p['count']} |" for p in report.get("curated_datatype_props", [])]
 
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
        graph = args.graph  
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
          f"subjects={report['distinct_subjects']} objects={report['distinct_objects']}"
          )
    
    print(f"[schema] Ditulis ke {out_dir}/knowledge_graph_schema.(json|md)")
    if report["triple_count"] in ("", "0"):
        print("[schema] CATATAN: 0 triple. Jika target lokal, pastikan Virtuoso jalan & data "
              "sudah dimuat (docker compose up; dump TTL ada di data/cskg_dumps/).")
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())