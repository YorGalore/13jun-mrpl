from pathlib import Path

from chatbot.api.sparql_client import (
    bindings_to_rows,
    list_classes,
    list_graphs,
    list_predicates,
    sample_triples,
)

OUTPUT = Path("docs/knowledge_graph_schema.md")


def md_table(rows, columns):
    if not rows:
        return "_No data found._"

    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(row.get(col, "") for col in columns) + " |")
    return "\n".join([header, separator] + body)


def main():
    graphs_result = bindings_to_rows(list_graphs(limit=50))
    graphs = [row["graph"] for row in graphs_result if "graph" in row]

    if not graphs:
        graphs = [None]

    lines = [
        "# SEPSES CSKG Schema Report",
        "",
        "Generated from Virtuoso SPARQL queries.",
        "",
    ]

    for graph_uri in graphs:
        title = graph_uri or "default graph"
        lines.extend([f"## Graph: {title}", ""])

        classes_rows = bindings_to_rows(list_classes(graph_uri=graph_uri, limit=20))
        predicates_rows = bindings_to_rows(list_predicates(graph_uri=graph_uri, limit=20))
        sample_rows = bindings_to_rows(sample_triples(graph_uri=graph_uri, limit=10))

        lines.extend(["### Top Classes", "", md_table(classes_rows, ["class", "count"]), ""])
        lines.extend(["### Top Predicates", "", md_table(predicates_rows, ["predicate", "count"]), ""])
        lines.extend(["### Sample Triples", "", md_table(sample_rows, ["s", "p", "o"]), ""])
        lines.append("")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote schema report to {OUTPUT}")


if __name__ == "__main__":
    main()