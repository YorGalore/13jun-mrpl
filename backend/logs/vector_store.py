"""
Vector log store (Issue #02) — ChromaDB + TF-IDF.

PERBAIKAN:
- Bug laten "embedding dimension mismatch": collection PersistentClient menyimpan
  embedding dari hasil fit TF-IDF proses sebelumnya, sementara setiap proses baru
  me-fit ulang vectorizer (dimensi bisa berbeda bila sample_logs.txt berubah) ->
  ChromaDB melempar error saat query. Solusi: collection dibangun ulang secara
  deterministik dari log saat ini sehingga dimensi tersimpan == dimensi query.
- Hanya ada SATU implementasi search_logs (modul_logs.py sekarang mendelegasi ke sini).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

import chromadb
from sklearn.feature_extraction.text import TfidfVectorizer

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "sample_logs.txt"
COLLECTION_NAME = "security_logs"

_DEFAULT_LOGS = [
    "Failed password for root from 192.168.1.105 port 22 ssh2",
    "New connection from 45.33.32.156 on port 4444 (possible reverse shell)",
    "sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
]

def load_logs(filepath: "str | os.PathLike" = DATA_FILE) -> List[str]:
    path = Path(filepath)
    if not path.exists():
        print(f"[vector_store] {path} tidak ditemukan, pakai sample default.")
        return list(_DEFAULT_LOGS)
    with open(path, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f if line.strip()]
    return logs or list(_DEFAULT_LOGS)

client = chromadb.PersistentClient(path="./vector_db")

_logs = load_logs()
_vectorizer = TfidfVectorizer()
_matrix = _vectorizer.fit_transform(_logs).toarray().tolist()

def _build_collection():
    """Bangun ulang collection agar dimensinya selalu sinkron dgn vectorizer saat ini."""
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass  # belum ada / tidak bisa dihapus -> abaikan
    coll = client.get_or_create_collection(name=COLLECTION_NAME)
    coll.add(
        documents=_logs,
        embeddings=_matrix,
        ids=[f"log_{i}" for i in range(len(_logs))],
    )
    return coll


collection = _build_collection()

def insert_log(doc_id: str, text: str) -> None:
    vec = _vectorizer.transform([text]).toarray().tolist()
    collection.add(ids=[doc_id], documents=[text], embeddings=vec)


def search_logs(query: str, n_results: int = 3) -> str:
    if collection.count() == 0:
        return "Tidak ada log yang termuat."
    query_vec = _vectorizer.transform([query]).toarray().tolist()
    results = collection.query(
        query_embeddings=query_vec,
        n_results=min(n_results, collection.count()),
    )
    docs = results["documents"][0]
    if not docs:
        return "Tidak ada log relevan ditemukan."
    out = f"=== Log relevan untuk: '{query}' ===\n"
    for i, doc in enumerate(docs, 1):
        out += f"[{i}] {doc}\n"
    return out

if __name__ == "__main__":
    print(search_logs("brute force SSH login"))
    print(search_logs("reverse shell connection"))