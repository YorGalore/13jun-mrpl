from typing import List, Dict

def build_structured_context(rows: List[Dict]):

    entities = []
    relationships = []

    for row in rows:

        for key, value in row.items():

            if "http" in value:
                entities.append(value)

        if len(row.keys()) >= 2:
            relationships.append(row)

    return {
        "entities": list(set(entities)),
        "relationships": relationships,
        "raw_results": rows
    }