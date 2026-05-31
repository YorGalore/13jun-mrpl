from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from chatbot.api.sparql_client import (
    DEFAULT_GRAPH,
    bindings_to_rows,
    count_distinct_entities,
    count_triples,
    count_instances_of,
    count_predicate_usage,
    
    describe_entity_neighbors,
    list_classes,
    list_named_graphs,
    list_predicates,
    sample_triples,
    sample_instances_of,
    search_labels,
)

CURATED_CLASSES: Sequence[Tuple[str, str]] = (
    ("cve:CVE", "CVE"),
    ("cwe:CWE", "CWE"),
    ("capec:AttackPattern", "CAPEC Attack Pattern"),
    ("attack:Technique", "ATT&CK Technique"),
    ("vuln:Vulnerability", "Vulnerability"),
    ("cpe:CPE", "CPE"),
    ("cvss:CVSS", "CVSS"),
)

CURATED_RELATIONS: Sequence[Tuple[str, str]] = (
    ("cve:hasCWE", "CVE → CWE"),
    ("cve:hasCAPEC", "CVE → CAPEC"),
    ("cve:hasCPE", "CVE → CPE"),
    ("cve:hasCVSS", "CVE → CVSS"),
    ("vuln:relatedTo", "Vulnerability → Related"),
    ("attack:targets", "ATT&CK → Targets"),
    ("attack:uses", "ATT&CK → Uses"),
)

@dataclass
class DiscoveryOptions:
    graph_uri: Optional[str] = None
    class_limit: int = 20
    predicate_limit: int = 20
    sample_limit: int = 10
    label_keyword: Optional[str] = None
    entity_iri: Optional[str] = None

@dataclass
class GraphReport:
    graph_uri: Optional[str]
    triple_count: List[Dict[str, str]] = field(default_factory=list)
    entity_count: List[Dict[str, str]] = field(default_factory=list)
    top_classes: List[Dict[str, str]] = field(default_factory=list)
    top_predicates: List[Dict[str, str]] = field(default_factory=list)
    sample_triples: List[Dict[str, str]] = field(default_factory=list)
    label_hits: List[Dict[str, str]] = field(default_factory=list)
    entity_neighborhood: List[Dict[str, str]] = field(default_factory=list)
    curated_classes: List[Dict[str, str]] = field(default_factory=list)
    curated_relations: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class DiscoveryReport:
    endpoint_graph: Optional[str]
    graph_count: int = 0
    graphs: List[Dict[str, str]] = field(default_factory=list)
    graphs_report: List[GraphReport] = field(default_factory=list)

class SepsesSchemaInspector:
    def __init__(self, graph_uri: Optional[str] = None):
        self.graph_uri = graph_uri or DEFAULT_GRAPH

    def discover_graphs(self) -> List[str]:
        rows = bindings_to_rows(list_named_graphs())
        graphs = [row["graph"] for row in rows if row.get("graph")]
        if self.graph_uri:
            return [self.graph_uri]
        return graphs or [None]

    def _build_graph_report(self, graph_uri: Optional[str], options: DiscoveryOptions) -> GraphReport:
        report = GraphReport(
            graph_uri=graph_uri,
            triple_count=bindings_to_rows(count_triples(graph_uri=graph_uri)),
            entity_count=bindings_to_rows(count_distinct_entities(graph_uri=graph_uri)),
            top_classes=bindings_to_rows(list_classes(graph_uri=graph_uri, limit=options.class_limit)),
            top_predicates=bindings_to_rows(list_predicates(graph_uri=graph_uri, limit=options.predicate_limit)),
            sample_triples=bindings_to_rows(sample_triples(graph_uri=graph_uri, limit=options.sample_limit)),
        )

        for class_term, label in CURATED_CLASSES:
            count_rows = bindings_to_rows(count_instances_of(class_term, graph_uri=graph_uri))
            count_value = count_rows[0]["count"] if count_rows else "0"
            samples = bindings_to_rows(sample_instances_of(class_term, graph_uri=graph_uri, limit=options.sample_limit))
            sample_values = []
            for sample in samples:
                entity = sample.get("entity", "")
                name = sample.get("label", "") or entity
                if name:
                    sample_values.append(name)

            report.curated_classes.append(
                {
                    "class": class_term,
                    "label": label,
                    "count": count_value,
                    "samples": "; ".join(sample_values[: options.sample_limit]),
                }
            )

        for predicate_term, label in CURATED_RELATIONS:
            count_rows = bindings_to_rows(count_predicate_usage(predicate_term, graph_uri=graph_uri))
            count_value = count_rows[0]["count"] if count_rows else "0"
            report.curated_relations.append(
                {
                    "predicate": predicate_term,
                    "label": label,
                    "count": count_value,
                }
            )

        if options.label_keyword:
            report.label_hits = bindings_to_rows(
                search_labels(options.label_keyword, graph_uri=graph_uri, limit=options.sample_limit)
            )
        if options.entity_iri:
            report.entity_neighborhood = bindings_to_rows(
                describe_entity_neighbors(options.entity_iri, graph_uri=graph_uri, limit=options.sample_limit)
            )

        return report

    def build_report(self, options: DiscoveryOptions) -> DiscoveryReport:
        graphs = self.discover_graphs()
        graphs_report = [self._build_graph_report(graph_uri, options) for graph_uri in graphs]

        return DiscoveryReport(
            endpoint_graph=self.graph_uri,
            graph_count=len(graphs),
            graphs=[{"graph": g or ""} for g in graphs],
            graphs_report=graphs_report,
        )

    @staticmethod
    def _table(rows: List[Dict[str, str]], columns: Sequence[str]) -> str:
        if not rows:
            return "_No data found._"
        header = "| " + " | ".join(columns) + " |"
        sep = "| " + " | ".join(["---"] * len(columns)) + " |"
        body = ["| " + " | ".join(row.get(col, "") for col in columns) + " |" for row in rows]
        return "\n".join([header, sep] + body)

    @staticmethod
    def _scalar(rows: List[Dict[str, str]], key: str, default: str = "n/a") -> str:
        if not rows:
            return default
        return rows[0].get(key, default) or default

    def render_markdown(self, report: DiscoveryReport) -> str:
        lines: List[str] = [
            "# SEPSES CSKG Schema Report",
            "",
            f"- Endpoint graph: `{report.endpoint_graph}`",
            f"- Graphs discovered: `{report.graph_count}`",
            "",
        ]

        for idx, gr in enumerate(report.graphs_report, start=1):
            lines.extend(
                [
                    f"## Graph {idx}: {gr.graph_uri or 'default graph'}",
                    "",
                    f"- Triples: `{self._scalar(gr.triple_count, 'triple_count')}`",
                    f"- Distinct subjects: `{self._scalar(gr.entity_count, 'subjects')}`",
                    f"- Distinct objects: `{self._scalar(gr.entity_count, 'objects')}`",
                    "",
                    "### Top Classes",
                    "",
                    self._table(gr.top_classes, ["class", "count"]),
                    "",
                    "### Top Predicates",
                    "",
                    self._table(gr.top_predicates, ["predicate", "count"]),
                    "",
                    "### Curated Security Classes",
                    "",
                    self._table(gr.curated_classes, ["class", "label", "count", "samples"]),
                    "",
                    "### Curated Security Relations",
                    "",
                    self._table(gr.curated_relations, ["predicate", "label", "count"]),
                    "",
                    "### Sample Triples",
                    "",
                    self._table(gr.sample_triples, ["s", "p", "o"]),
                    "",
                ]
            )

            if gr.label_hits:
                lines.extend(
                    [
                        "### Label Search Results",
                        "",
                        self._table(gr.label_hits, ["s", "label"]),
                        "",
                    ]
                )

            if gr.entity_neighborhood:
                lines.extend(
                    [
                        "### Entity Neighborhood",
                        "",
                        self._table(gr.entity_neighborhood, ["direction", "predicate", "predicateLabel", "neighbor"]),
                        "",
                    ]
                )

        return "\n".join(lines).strip() + "\n"

    def to_json(self, report: DiscoveryReport) -> Dict[str, Any]:
        return {
            "endpoint_graph": report.endpoint_graph,
            "graph_count": report.graph_count,
            "graphs": report.graphs,
            "graphs_report": [
                {
                    "graph_uri": gr.graph_uri,
                    "triple_count": gr.triple_count,
                    "entity_count": gr.entity_count,
                    "top_classes": gr.top_classes,
                    "top_predicates": gr.top_predicates,
                    "sample_triples": gr.sample_triples,
                    "label_hits": gr.label_hits,
                    "entity_neighborhood": gr.entity_neighborhood,
                    "curated_classes": gr.curated_classes,
                    "curated_relations": gr.curated_relations,
                }
                for gr in report.graphs_report
            ],
        }

    def save_report(self, report: DiscoveryReport, output_dir: str | Path) -> tuple[Path, Path]:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # disamakan dengan ontology_context.py
        json_path = output_path / "knowledge_graph_schema.json"
        md_path = output_path / "knowledge_graph_schema.md"

        json_path.write_text(json.dumps(self.to_json(report), indent=2, ensure_ascii=False), encoding="utf-8")
        md_path.write_text(self.render_markdown(report), encoding="utf-8")
        return json_path, md_path

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect SEPSES CSKG structure through a SPARQL endpoint.")
    parser.add_argument("--graph", default=None, help="Inspect only one graph URI.")
    parser.add_argument("--class-limit", type=int, default=20)
    parser.add_argument("--predicate-limit", type=int, default=20)
    parser.add_argument("--sample-limit", type=int, default=10)
    parser.add_argument("--label", default=None, help="Keyword for rdfs:label search.")
    parser.add_argument("--entity", default=None, help="Entity IRI to inspect neighborhood.")
    parser.add_argument("--output-dir", default="docs", help="Directory to write JSON/Markdown report.")
    return parser

def main() -> None:
    args = build_arg_parser().parse_args()
    inspector = SepsesSchemaInspector(graph_uri=args.graph or DEFAULT_GRAPH)
    options = DiscoveryOptions(
        graph_uri=args.graph,
        class_limit=args.class_limit,
        predicate_limit=args.predicate_limit,
        sample_limit=args.sample_limit,
        label_keyword=args.label,
        entity_iri=args.entity,
    )
    report = inspector.build_report(options)
    json_path, md_path = inspector.save_report(report, args.output_dir)

    print(f"Saved JSON report: {json_path}")
    print(f"Saved Markdown report: {md_path}")
    print()
    print(inspector.render_markdown(report))

if __name__ == "__main__":
    main()
