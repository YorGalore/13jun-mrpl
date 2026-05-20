from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

SAMPLE_LOGS = [
    "Failed password for root from 192.168.1.105 port 22 ssh2",
    "Failed password for invalid user admin from 10.0.0.5 port 3389",
    "Accepted publickey for user from 192.168.1.2 port 22",
    "sudo: user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    "segfault at 0 ip 00007f error 4 in libc.so",
    "iptables: DROP IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=22",
    "PHP Warning: file_get_contents(http://malicious.com/shell.php)",
    "GET /etc/passwd HTTP/1.1 400 from 192.168.1.200",
    "Possible SYN flood on port 80",
    "New connection from 45.33.32.156 on port 4444 (possible reverse shell)",
]

# Build TF-IDF index dari log
vectorizer = TfidfVectorizer()
log_matrix = vectorizer.fit_transform(SAMPLE_LOGS)
print(f"{len(SAMPLE_LOGS)} log berhasil dimuat.")

def search_logs(query: str, n_results: int = 3) -> str:
    query_vec = vectorizer.transform([query])
    scores = cosine_similarity(query_vec, log_matrix)[0]
    top_indices = np.argsort(scores)[::-1][:n_results]

    context = f"=== Log relevan untuk: '{query}' ===\n"
    for i, idx in enumerate(top_indices, 1):
        if scores[idx] > 0:
            context += f"[{i}] {SAMPLE_LOGS[idx]}\n"

    if context == f"=== Log relevan untuk: '{query}' ===\n":
        return "Tidak ada log relevan ditemukan."

    return context

if __name__ == "__main__":
    print()
    print(search_logs("brute force SSH login"))
    print()
    print(search_logs("reverse shell connection"))
    print()
    print(search_logs("privilege escalation sudo"))