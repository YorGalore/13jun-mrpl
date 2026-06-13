from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend.config import CHROMA_DIR, LOGS_FILE

_COLLECTION_NAME = "security_logs"
_CHUNK_MAX_CHARS = 512 

LOG_TYPES = ("auth", "syslog", "web_access", "ids_alert", "firewall", "unknown")
 
_DEFAULT_LOGS = [
    "[auth] Failed password for root from 192.168.1.105 port 22 ssh2",
    "[ids_alert] [1:2010935:3] ET POLICY Suspicious inbound to mySQL port 3306 [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 45.33.32.156:51234 -> 10.0.0.5:3306",
    "[auth] sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
]

_TAG_RE = re.compile(r"^\s*\[(auth|syslog|web_access|ids_alert|firewall)\]\s*", re.IGNORECASE)

_WEB_ACCESS_RE = re.compile(r'"\s*(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/\d', re.IGNORECASE)
_SNORT_RE = re.compile(r"\[\d+:\d+:\d+\]|\[Classification:|\[Priority:\s*\d+\]", re.IGNORECASE)
_AUTH_RE = re.compile(
    r"\b(sshd?|sudo|su|pam_unix|authentication failure|failed password|"
    r"accepted password|invalid user|session opened|session closed)\b",
    re.IGNORECASE,
)
_FIREWALL_RE = re.compile(r"\b(UFW|iptables|nftables|firewalld|kernel:.*\b(SRC|DST)=)\b", re.IGNORECASE)
_SYSLOG_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|"  # "Oct 16 12:00:00"
    r"<\d{1,3}>\d?\s",                                   # PRI syslog "<34>1 ..."
    re.IGNORECASE,
)
 
def classify_log(line: str) -> Tuple[str, str]:
    raw = (line or "").strip()
    if not raw:
        return "unknown", ""
    
    m = _TAG_RE.match(raw)
    if m:
        return m.group(1).lower(), _TAG_RE.sub("", raw, count=1).strip()
    
    if _WEB_ACCESS_RE.search(raw):
        return "web_access", raw
    if _SNORT_RE.search(raw):
        return "ids_alert", raw
    if _AUTH_RE.search(raw):
        return "auth", raw
    if _FIREWALL_RE.search(raw):
        return "firewall", raw
    if _SYSLOG_RE.search(raw):
        return "syslog", raw
    return "unknown", raw


# LOADING & CHUNKING
def load_logs(filepath: "str | Path" = LOGS_FILE) -> List[str]:
    """Baca file log per-baris (1 baris = 1 event). Abaikan baris komentar (#).
    Fallback ke sample default bila file tak ada/ kosong."""
    path = Path(filepath)
    if not path.is_file():
        print(f"[logs] {path} bukan file valid, pakai sample default.")
        return list(_DEFAULT_LOGS)
    with open(path, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")]
    return logs or list(_DEFAULT_LOGS)
 
 
def _chunk_one(line: str, max_chars: int = _CHUNK_MAX_CHARS) -> List[str]:
    line = line.strip()
    if len(line) <= max_chars:
        return [line] if line else []
    words, chunks, buf = line.split(), [], ""
    for w in words:
        if buf and len(buf) + 1 + len(w) > max_chars:
            chunks.append(buf)
            buf = w
        else:
            buf = f"{buf} {w}".strip()
    if buf:
        chunks.append(buf)
    return chunks

def _stable_id(text: str, log_type: str = "") -> str:
    """ID deterministik dari isi (+tipe) -> ingest idempoten (tak duplikat saat restart)."""
    basis = f"{log_type}|{text}" if log_type else text
    return "log-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]
 
 
def _prepare(lines: List[str]) -> List[Tuple[str, str]]:
    """Dari baris mentah -> daftar (chunk_text, log_type). Klasifikasi sekali per baris,
    lalu pecah panjang >512 char menjadi beberapa chunk yang mewarisi tipe yang sama."""
    out: List[Tuple[str, str]] = []
    for ln in lines:
        log_type, clean = classify_log(ln)
        for c in _chunk_one(clean):
            if c:
                out.append((c, log_type))
    return out

# ChromaDB
class _ChromaBackend:
    label = "ChromaDB (vector)"
 
    def __init__(self) -> None:
        import chromadb
        from chromadb.utils import embedding_functions
 
        Path(CHROMA_DIR).mkdir(parents=True, exist_ok=True)
 
        self._embed = embedding_functions.DefaultEmbeddingFunction()
        self._client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self._col = self._client.get_or_create_collection(
            name=_COLLECTION_NAME,
            embedding_function=self._embed,
            metadata={"hnsw:space": "cosine"},
        )
        self._ingest(_prepare(load_logs()), source="sample_logs")
 
    def _ingest(self, items: List[Tuple[str, str]], source: str) -> None:
        items = [(t, lt) for (t, lt) in items if t]
        if not items:
            return
        seen, u_ids, u_docs, u_metas = set(), [], [], []
        for text, log_type in items:
            sid = _stable_id(text, log_type)
            if sid in seen:
                continue
            seen.add(sid)
            u_ids.append(sid)
            u_docs.append(text)
            u_metas.append({"source": source, "log_type": log_type, "chars": len(text)})
        self._col.upsert(ids=u_ids, documents=u_docs, metadatas=u_metas)
 
    def insert(self, doc_id: str, text: str, log_type: Optional[str] = None) -> int:
        """Tambah satu/lebih event. Tiap baris diklasifikasi (atau pakai log_type paksaan).
        Kembalikan jumlah chunk yang ter-upsert."""
        text = (text or "").strip()
        if not text:
            return 0
        items: List[Tuple[str, str]] = []
        for raw_line in text.splitlines() or [text]:
            if not raw_line.strip():
                continue
            lt, clean = classify_log(raw_line)
            if log_type:  # override eksplisit dari pemanggil/endpoint
                lt = log_type.lower()
            for c in _chunk_one(clean):
                if c:
                    items.append((c, lt))
        self._ingest(items, source=doc_id or "runtime")
        return len(items)
 
    def search(self, query: str, n_results: int, log_type: Optional[str] = None) -> List[Tuple[str, float, str]]:
        count = self._col.count()
        if count == 0:
            return []
        where = {"log_type": log_type.lower()} if log_type else None
        res = self._col.query(
            query_texts=[query or ""],
            n_results=min(n_results, count),
            where=where,
        )
        docs = (res.get("documents") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        hits: List[Tuple[str, float, str]] = []
        for doc, dist, meta in zip(docs, dists, metas):
            sim = max(0.0, min(1.0, 1.0 - float(dist)))  # cosine distance -> similarity
            lt = (meta or {}).get("log_type", "unknown")
            hits.append((doc, sim, lt))
        return hits
 
    def stats(self) -> Dict[str, int]:
        total = self._col.count()
        out: Dict[str, int] = {"total": total}
        for lt in LOG_TYPES:
            try:
                out[lt] = len(self._col.get(where={"log_type": lt}).get("ids", []))
            except Exception:
                out[lt] = 0
        return out
 
 
# TF-IDF in-memory (fallback bila Chroma tidak tersedia)
class _TfidfBackend:
    label = "TF-IDF in-memory (fallback)"
 
    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
 
        self._cosine = cosine_similarity
        prepared = _prepare(load_logs()) or [(d, classify_log(d)[0]) for d in _DEFAULT_LOGS]
        self._docs: List[str] = [t for (t, _) in prepared]
        self._types: List[str] = [lt for (_, lt) in prepared]
        self._vectorizer = TfidfVectorizer()
        self._matrix = self._vectorizer.fit_transform(self._docs)
 
    def _reindex(self) -> None:
        self._matrix = self._vectorizer.fit_transform(self._docs)
 
    def insert(self, doc_id: str, text: str, log_type: Optional[str] = None) -> int:
        text = (text or "").strip()
        if not text:
            return 0
        added = 0
        for raw_line in text.splitlines() or [text]:
            if not raw_line.strip():
                continue
            lt, clean = classify_log(raw_line)
            if log_type:
                lt = log_type.lower()
            for c in _chunk_one(clean):
                if c:
                    self._docs.append(c)
                    self._types.append(lt)
                    added += 1
        if added:
            self._reindex()
        return added
 
    def search(self, query: str, n_results: int, log_type: Optional[str] = None) -> List[Tuple[str, float, str]]:
        if not self._docs:
            return []
        qv = self._vectorizer.transform([query or ""])
        scores = self._cosine(qv, self._matrix)[0]
        order = scores.argsort()[::-1]
        hits: List[Tuple[str, float, str]] = []
        want = log_type.lower() if log_type else None
        for i in order:
            if scores[i] <= 0:
                continue
            if want and self._types[i] != want:
                continue
            hits.append((self._docs[i], float(scores[i]), self._types[i]))
            if len(hits) >= n_results:
                break
        return hits
 
    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {"total": len(self._docs)}
        for lt in LOG_TYPES:
            out[lt] = sum(1 for t in self._types if t == lt)
        return out
 
 
# PEMILIHAN BACKEND (sekali saat modul dimuat)
def _init_backend():
    try:
        be = _ChromaBackend()
        print(f"[logs] backend aktif: {be.label} (dir={CHROMA_DIR})")
        return be
    except Exception as e:
        print(f"[logs] ChromaDB tidak tersedia ({str(e)[:160]}); fallback ke TF-IDF in-memory.")
    try:
        be = _TfidfBackend()
        print(f"[logs] backend aktif: {be.label}")
        return be
    except Exception as e:
        print(f"[logs] TF-IDF juga gagal ({str(e)[:160]}); pencarian log dinonaktifkan.")
        return None
 
 
_BACKEND = _init_backend()


# API PUBLIK 
def backend_label() -> str:
    return _BACKEND.label if _BACKEND else "Tidak aktif"
 
 
def insert_log(doc_id: str, text: str, log_type: Optional[str] = None) -> int:
    """Tambah log runtime ke vector DB. Kembalikan jumlah chunk yang ditambahkan."""
    if not _BACKEND:
        return 0
    if log_type and log_type.lower() not in LOG_TYPES:
        log_type = None  # tipe tak dikenal -> biarkan auto-klasifikasi
    return _BACKEND.insert(doc_id, text, log_type=log_type)
 
 
def log_stats() -> Dict[str, int]:
    return _BACKEND.stats() if _BACKEND else {"total": 0}
 
 
def search_logs(query: str, n_results: int = 3, log_type: Optional[str] = None) -> str:
    if not _BACKEND:
        return "Tidak ada log yang termuat (backend pencarian log tidak aktif)."
 
    if log_type and log_type.lower() not in LOG_TYPES:
        log_type = None
    hits = _BACKEND.search(query, n_results, log_type=log_type)
    if not hits:
        scope = f" (tipe={log_type})" if log_type else ""
        return f"Tidak ada log relevan ditemukan untuk: '{query}'{scope}"
 
    scope = f", tipe={log_type}" if log_type else ""
    out = f"=== Log relevan untuk: '{query}'{scope} (sumber: {backend_label()}) ===\n"
    for rank, (doc, score, lt) in enumerate(hits, 1):
        out += f"[{rank}] ({score:.2f}) [{lt}] {doc}\n"
    return out