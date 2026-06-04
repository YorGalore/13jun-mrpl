from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, Tuple

from backend.config import CHROMA_DIR, LOGS_FILE

_COLLECTION_NAME = "security_logs"
_CHUNK_MAX_CHARS = 512 

_DEFAULT_LOGS = [
    "Failed password for root from 192.168.1.105 port 22 ssh2",
    "New connection from 45.33.32.156 on port 4444 (possible reverse shell)",
    "sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
]

# LOADING & CHUNKING
def load_logs(filepath: "str | Path" = LOGS_FILE) -> List[str]:
    """Baca file log per-baris (1 baris = 1 event). Fallback ke sample default."""
    path = Path(filepath)
    if not path.is_file():  
        print(f"[logs] {path} bukan file valid, pakai sample default.")
        return list(_DEFAULT_LOGS)
    with open(path, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f if line.strip()]
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


def _chunk_logs(lines: List[str], max_chars: int = _CHUNK_MAX_CHARS) -> List[str]:
    chunks: List[str] = []
    for ln in lines:
        chunks.extend(_chunk_one(ln, max_chars))
    return chunks


def _stable_id(text: str) -> str:
    """ID deterministik dari isi -> ingest idempoten (tidak menduplikasi saat restart)."""
    return "log-" + hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


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
        self._ingest(_chunk_logs(load_logs()))

    def _ingest(self, chunks: List[str]) -> None:
        chunks = [c for c in chunks if c]
        if not chunks:
            return
        ids = [_stable_id(c) for c in chunks]
        seen, u_ids, u_docs = set(), [], []
        for i, c in zip(ids, chunks):
            if i in seen:
                continue
            seen.add(i)
            u_ids.append(i)
            u_docs.append(c)
        metas = [{"source": "sample_logs", "chars": len(c)} for c in u_docs]
        self._col.upsert(ids=u_ids, documents=u_docs, metadatas=metas)

    def insert(self, doc_id: str, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        for c in _chunk_one(text):
            self._col.upsert(ids=[_stable_id(c)], documents=[c],
                             metadatas=[{"source": doc_id or "runtime", "chars": len(c)}])

    def search(self, query: str, n_results: int) -> List[Tuple[str, float]]:
        count = self._col.count()
        if count == 0:
            return []
        res = self._col.query(query_texts=[query or ""], n_results=min(n_results, count))
        docs = (res.get("documents") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        hits: List[Tuple[str, float]] = []
        for doc, dist in zip(docs, dists):
            # cosine distance -> similarity (clamp ke [0,1] agar tampilan rapi)
            sim = max(0.0, min(1.0, 1.0 - float(dist)))
            hits.append((doc, sim))
        return hits


# TF-IDF in-memory (fallback bila Chroma tidak tersedia)
class _TfidfBackend:
    label = "TF-IDF in-memory (fallback)"

    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        self._cosine = cosine_similarity
        self._docs: List[str] = _chunk_logs(load_logs()) or list(_DEFAULT_LOGS)
        self._vectorizer = TfidfVectorizer()
        self._matrix = self._vectorizer.fit_transform(self._docs)

    def _reindex(self) -> None:
        self._matrix = self._vectorizer.fit_transform(self._docs)

    def insert(self, doc_id: str, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        for c in _chunk_one(text):
            self._docs.append(c)
        self._reindex()

    def search(self, query: str, n_results: int) -> List[Tuple[str, float]]:
        if not self._docs:
            return []
        qv = self._vectorizer.transform([query or ""])
        scores = self._cosine(qv, self._matrix)[0]
        ranked = scores.argsort()[::-1][:n_results]
        return [(self._docs[i], float(scores[i])) for i in ranked if scores[i] > 0]


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


def insert_log(doc_id: str, text: str) -> None:
    if _BACKEND:
        _BACKEND.insert(doc_id, text)


def search_logs(query: str, n_results: int = 3) -> str:
    if not _BACKEND:
        return "Tidak ada log yang termuat (backend pencarian log tidak aktif)."

    hits = _BACKEND.search(query, n_results)
    if not hits:
        return f"Tidak ada log relevan ditemukan untuk: '{query}'"

    out = f"=== Log relevan untuk: '{query}' (sumber: {backend_label()}) ===\n"
    for rank, (doc, score) in enumerate(hits, 1):
        out += f"[{rank}] ({score:.2f}) {doc}\n"
    return out