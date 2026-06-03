"""
GATEWAY 3 — Log keamanan (SELALU lokal).

Satu-satunya pintu untuk analisis log. Sumber: file lokal sample_logs.txt.
Pencarian relevansi memakai TF-IDF + cosine similarity (scikit-learn) di memori.

Catatan: versi ini sengaja TIDAK memakai ChromaDB. Komponen native/rust
ChromaDB gagal membuka database SQLite di sebagian lingkungan (mis. Python 3.14),
sedangkan untuk pencarian log sederhana TF-IDF in-memory sudah cukup, lebih ringan,
dan tanpa dependensi/berkas database eksternal. API publik tetap sama:
search_logs(), insert_log(), load_logs(). Hanya bergantung pada backend.config.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from backend.config import LOGS_FILE

_DEFAULT_LOGS = [
    "Failed password for root from 192.168.1.105 port 22 ssh2",
    "New connection from 45.33.32.156 on port 4444 (possible reverse shell)",
    "sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
]


def load_logs(filepath: "str | Path" = LOGS_FILE) -> List[str]:
    path = Path(filepath)
    if not path.is_file():  # is_file() False utk path kosong ('.') / direktori / tidak ada
        print(f"[logs] {path} bukan file valid, pakai sample default.")
        return list(_DEFAULT_LOGS)
    with open(path, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f if line.strip()]
    return logs or list(_DEFAULT_LOGS)


# --- bangun indeks sekali saat modul dimuat (in-memory, tanpa file DB) ---
_logs: List[str] = load_logs()
_vectorizer = TfidfVectorizer()
_matrix = _vectorizer.fit_transform(_logs)


def _reindex() -> None:
    """Hitung ulang matriks TF-IDF dari daftar log saat ini."""
    global _matrix
    _matrix = _vectorizer.fit_transform(_logs)


def insert_log(doc_id: str, text: str) -> None:
    """Tambah satu log baru lalu indeks ulang. doc_id dipertahankan demi kompatibilitas API."""
    text = (text or "").strip()
    if not text:
        return
    _logs.append(text)
    _reindex()


def search_logs(query: str, n_results: int = 3) -> str:
    if not _logs:
        return "Tidak ada log yang termuat."

    query_vec = _vectorizer.transform([query or ""])
    scores = cosine_similarity(query_vec, _matrix)[0]
    ranked = scores.argsort()[::-1][:n_results]

    hits = [(_logs[i], float(scores[i])) for i in ranked if scores[i] > 0]
    if not hits:
        return f"Tidak ada log relevan ditemukan untuk: '{query}'"

    out = f"=== Log relevan untuk: '{query}' ===\n"
    for rank, (doc, score) in enumerate(hits, 1):
        out += f"[{rank}] ({score:.2f}) {doc}\n"
    return out