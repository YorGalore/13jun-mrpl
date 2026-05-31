import chromadb
import os

# Setup ChromaDB dengan embedding manual (tanpa download model)
client = chromadb.Client()
collection = client.get_or_create_collection(name="security_logs")

def load_logs(filepath: str = "sample_logs.txt") -> list:
    if not os.path.exists(filepath):
        print(f"File {filepath} tidak ditemukan, pakai sample default.")
        return [
            "Failed password for root from 192.168.1.105 port 22 ssh2",
            "New connection from 45.33.32.156 on port 4444 (possible reverse shell)",
            "sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        ]
    with open(filepath, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f.readlines() if line.strip()]
    return logs

def load_to_chromadb():
    # Cek apakah sudah ada data
    if collection.count() > 0:
        print(f"{collection.count()} log sudah ada di ChromaDB.")
        return
    
    logs = load_logs()
    
    # Buat embedding sederhana dari TF-IDF manual
    from sklearn.feature_extraction.text import TfidfVectorizer
    vectorizer = TfidfVectorizer()
    matrix = vectorizer.fit_transform(logs).toarray().tolist()
    
    collection.add(
        documents=logs,
        embeddings=matrix,
        ids=[f"log_{i}" for i in range(len(logs))]
    )
    print(f"{len(logs)} log berhasil dimuat ke ChromaDB.")
    return vectorizer

# Load saat modul diimport
from sklearn.feature_extraction.text import TfidfVectorizer
_logs = load_logs()
_vectorizer = TfidfVectorizer()
_matrix = _vectorizer.fit_transform(_logs).toarray().tolist()

if collection.count() == 0:
    collection.add(
        documents=_logs,
        embeddings=_matrix,
        ids=[f"log_{i}" for i in range(len(_logs))]
    )
    print(f"{len(_logs)} log berhasil dimuat ke ChromaDB.")
else:
    print(f"{collection.count()} log sudah ada di ChromaDB.")

def search_logs(query: str, n_results: int = 3) -> str:
    query_vec = _vectorizer.transform([query]).toarray().tolist()
    results = collection.query(
        query_embeddings=query_vec,
        n_results=min(n_results, collection.count())
    )
    docs = results["documents"][0]
    if not docs:
        return "Tidak ada log relevan ditemukan."
    context = f"=== Log relevan untuk: '{query}' ===\n"
    for i, doc in enumerate(docs, 1):
        context += f"[{i}] {doc}\n"
    return context

if __name__ == "__main__":
    print()
    print(search_logs("brute force SSH login"))
    print()
    print(search_logs("reverse shell connection"))
    print()
    print(search_logs("malware detected"))
    print()
    print(search_logs("SQL injection"))