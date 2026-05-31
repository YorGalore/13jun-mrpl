#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

VIRTUOSO_CONTAINER="virtuoso"
VIRTUOSO_DB_PATH="/database"
ISQL="/opt/virtuoso-opensource/bin/isql"

echo "======================================"
echo " SEPSES RDF Loader for Virtuoso "
echo "======================================"

rdf_files=(data/*.ttl data/*.turtle)

if [ ${#rdf_files[@]} -eq 0 ]; then
  echo "No RDF files found in data/ (*.ttl or *.turtle)"
  exit 0
fi

for rdf_file in "${rdf_files[@]}"; do
  graph_file="${rdf_file}.graph"

  if [ ! -f "$graph_file" ]; then
    echo "Skipping $(basename "$rdf_file") (missing .graph file)"
    continue
  fi

  graph_uri="$(cat "$graph_file")"
  filename="$(basename "$rdf_file")"

  echo ""
  echo "--------------------------------------"
  echo "Loading: $filename"
  echo "Graph  : $graph_uri"
  echo "--------------------------------------"

  docker cp "$rdf_file" "${VIRTUOSO_CONTAINER}:${VIRTUOSO_DB_PATH}/${filename}"

  docker exec "${VIRTUOSO_CONTAINER}" \
    ${ISQL} 1111 dba dba exec="ld_dir('${VIRTUOSO_DB_PATH}', '${filename}', '${graph_uri}'); rdf_loader_run(); checkpoint;"

  echo "Finished loading $filename"
done

echo ""
echo "======================================"
echo " All RDF dumps loaded successfully "
echo "======================================"