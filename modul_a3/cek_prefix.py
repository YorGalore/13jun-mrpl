from SPARQLWrapper import SPARQLWrapper, JSON
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

sparql = SPARQLWrapper("https://sepses.ifs.tuwien.ac.at/sparql")

query = """
PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>

SELECT ?p ?o WHERE {
  GRAPH <http://w3id.org/sepses/resource/attack/intrusion-set--00f67a77-86a4-4adf-be26-1a54fc713340> {
    ?s ?p ?o .
  }
} LIMIT 30
"""

sparql.setQuery(query)
sparql.setReturnFormat(JSON)
results = sparql.query().convert()

for row in results["results"]["bindings"]:
    print(f"{row['p']['value']} = {str(row['o']['value'])[:100]}")