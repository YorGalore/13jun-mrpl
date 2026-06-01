#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

VIRTUOSO_CONTAINER="${VIRTUOSO_CONTAINER:-virtuoso}"
VIRTUOSO_DB_PATH="${VIRTUOSO_DB_PATH:-/database}"
ISQL="${ISQL:-/opt/virtuoso-opensource/bin/isql}"
TARGET_GRAPH="${SEPSES_LOCAL_GRAPH:-http://sepses.local}"

echo "======================================"
echo " SEPSES RDF Loader for Virtuoso "
echo " Target graph: ${TARGET_GRAPH}"
echo "======================================"

echo -n "Menunggu Virtuoso siap"
for _ in $(seq 1 30); do
  if docker exec "${VIRTUOSO_CONTAINER}" ${ISQL} 1111 dba dba exec="status();" >/dev/null 2>&1; then
    echo " -> siap."
    break
  fi
  echo -n "."
  sleep 2
done

rdf_files=(data/cskg_dumps/*.ttl data/cskg_dumps/*.turtle)

if [ ${#rdf_files[@]} -eq 0 ]; then
  echo "No RDF files found in data/ (*.ttl or *.turtle)"
  exit 0
fi

for rdf_file in "${rdf_files[@]}"; do
  filename="$(basename "$rdf_file")"
  echo ""
  echo "--------------------------------------"
  echo "Loading: ${filename}  ->  ${TARGET_GRAPH}"
  echo "--------------------------------------"
  docker cp "$rdf_file" "${VIRTUOSO_CONTAINER}:${VIRTUOSO_DB_PATH}/${filename}"
  docker exec "${VIRTUOSO_CONTAINER}" \
    ${ISQL} 1111 dba dba exec="ld_dir('${VIRTUOSO_DB_PATH}', '${filename}', '${TARGET_GRAPH}'); rdf_loader_run(); checkpoint;"
  echo "Selesai: ${filename}"
done

echo ""
echo "Verifikasi jumlah triple di ${TARGET_GRAPH}:"
docker exec "${VIRTUOSO_CONTAINER}" \
  ${ISQL} 1111 dba dba exec="SPARQL SELECT COUNT(*) WHERE { GRAPH <${TARGET_GRAPH}> { ?s ?p ?o } };"

echo ""
echo "Selesai. Endpoint lokal: http://localhost:8890/sparql"
