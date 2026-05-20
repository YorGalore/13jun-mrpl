from SPARQLWrapper import SPARQLWrapper, JSON
import ssl
import certifi

# Fix SSL certificate
ssl._create_default_https_context = ssl._create_unverified_context

sparql = SPARQLWrapper("https://sepses.ifs.tuwien.ac.at/sparql")

query = """
PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>

SELECT ?cveId WHERE {
  ?cve cve:id ?cveId .
} LIMIT 5
"""

sparql.setQuery(query)
sparql.setReturnFormat(JSON)
results = sparql.query().convert()

for row in results["results"]["bindings"]:
    print(row["cveId"]["value"])