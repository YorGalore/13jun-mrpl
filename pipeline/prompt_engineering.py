import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from modul_vulnerability import get_vuln_context
from modul_threat import get_threat_context, get_malware_context
from modul_logs import search_logs

# System prompt untuk LLM
SYSTEM_PROMPT = """Kamu adalah analis keamanan siber yang ahli.
Jawab pertanyaan pengguna HANYA berdasarkan konteks data yang diberikan.
Jangan mengarang informasi di luar konteks.
Berikan jawaban yang jelas, terstruktur, dan actionable.
Jika data tidak tersedia, katakan dengan jujur."""

def build_prompt(user_question: str) -> dict:
    """
    Deteksi jenis pertanyaan dan ambil konteks yang relevan,
    lalu bangun prompt siap kirim ke LLM.
    """
    question_lower = user_question.lower()
    context = ""

    # Deteksi CVE
    import re
    cve_match = re.search(r'cve-\d{4}-\d+', question_lower)
    if cve_match:
        cve_id = cve_match.group().upper()
        context += get_vuln_context(cve_id)

    # Deteksi threat actor
    threat_keywords = ["apt", "lazarus", "fancy bear", "cozy bear", "kimsuky",
                       "sandworm", "carbanak", "fin7", "turla"]
    for kw in threat_keywords:
        if kw in question_lower:
            context += get_threat_context(kw)
            break

    # Deteksi malware
    malware_keywords = ["wannacry", "emotet", "mirai", "stuxnet", "notpetya",
                        "ransomware", "trojan", "rootkit", "cobalt strike"]
    for kw in malware_keywords:
        if kw in question_lower:
            context += get_malware_context(kw)
            break

    # Deteksi log analysis
    log_keywords = ["log", "ssh", "login", "failed", "connection", "brute",
                    "intrusion", "anomali", "mencurigakan"]
    for kw in log_keywords:
        if kw in question_lower:
            context += search_logs(user_question)
            break

    # Bangun prompt final
    if context:
        user_message = f"""Konteks data keamanan:
{context}

Pertanyaan: {user_question}"""
    else:
        user_message = f"""Pertanyaan: {user_question}
(Tidak ada data spesifik ditemukan di knowledge graph untuk pertanyaan ini.)"""

    return {
        "system": SYSTEM_PROMPT,
        "user": user_message
    }


# Test
if __name__ == "__main__":
    pertanyaan = [
        "Apa bahaya dari CVE-2017-0144?",
        "Ceritakan tentang APT28",
        "Apa itu WannaCry dan bagaimana cara kerjanya?",
        "Ada log mencurigakan terkait reverse shell tidak?",
    ]

    for p in pertanyaan:
        print(f"\nPERTANYAAN: {p}")
        print("-" * 50)
        hasil = build_prompt(p)
        print("SYSTEM:", hasil["system"][:80], "...")
        print("USER MSG:\n", hasil["user"])
        print("=" * 60)