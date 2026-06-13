set -uo pipefail

HOST="${VIRTUOSO_HOST:-virtuoso}"
PORT="${VIRTUOSO_PORT:-1111}"
PW="${DBA_PASSWORD:-dba}"
GRAPH="${TARGET_GRAPH:-http://sepses.local}"
DB_DIR="${DB_DIR:-/dumps}"
ISQL="/opt/virtuoso-opensource/bin/isql"
CONN="${HOST}:${PORT}"

isql_exec() { "${ISQL}" "${CONN}" dba "${PW}" "exec=$1"; }

echo "[loader] target=${CONN} graph=${GRAPH} dir=${DB_DIR}"

# 1) Tunggu Virtuoso siap 
echo -n "[loader] menunggu Virtuoso siap"
ready=0
for _ in $(seq 1 60); do
  if isql_exec "status();" >/dev/null 2>&1; then ready=1; echo " -> siap"; break; fi
  echo -n "."; sleep 2
done
if [ "${ready}" -ne 1 ]; then
  echo ""
  echo "[loader] Virtuoso tidak merespons; load dilewati (backend pakai endpoint publik)."
  exit 0
fi

# 2) Idempoten: lewati bila graph sudah berisi triple.
count="$(isql_exec "SPARQL SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${GRAPH}> { ?s ?p ?o } };" 2>/dev/null \
          | grep -Eo '^[0-9]+$' | head -1)"
count="${count:-0}"
if [ "${count}" -gt 0 ] 2>/dev/null; then
  echo "[loader] graph sudah berisi ${count} triple; load dilewati."
  exit 0
fi

# 3) Muat semua *.ttl dari direktori dump (data/cskg_dumps, di-mount sbg ${DB_DIR}).
echo "[loader] memuat *.ttl dari ${DB_DIR} -> ${GRAPH} ..."
isql_exec "ld_dir('${DB_DIR}', '*.ttl', '${GRAPH}'); rdf_loader_run(); checkpoint;" || {
  echo "[loader] perintah load mengembalikan error; cek dump di data/cskg_dumps/."
}

# 4) Laporkan error loader (kosong = sukses) dan jumlah triple akhir.
echo "[loader] error loader (kosong = sukses):"
isql_exec "SELECT ll_file, ll_error FROM DB.DBA.LOAD_LIST WHERE ll_error IS NOT NULL;" || true
echo "[loader] jumlah triple di ${GRAPH}:"
isql_exec "SPARQL SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${GRAPH}> { ?s ?p ?o } };" || true

echo "[loader] selesai. Endpoint lokal: http://localhost:8890/sparql (graph ${GRAPH})."
exit 0