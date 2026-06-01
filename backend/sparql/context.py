from typing import Any, List, Dict

def build_structured_context(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    entities: List[str] = []
    relationships: List[Dict[str, Any]] = []

    for row in rows:
        for value in row.values():
            if isinstance(value, str) and value.startswith("http"):
                entities.append(value)
        if len(row.keys()) >= 2:
            relationships.append(row)

    return {
        "entities": list(dict.fromkeys(entities)),  # unik + stabil urutannya
        "relationships": relationships,
        "raw_results": rows,
    }