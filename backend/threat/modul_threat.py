#Ditambah 
from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from mitreattack.stix20 import MitreAttackData

_ROOT = Path(__file__).resolve().parents[2]
# Urutan pencarian dataset: lokasi standar (data/) dulu, lalu yang ikut ter-commit (modul_a3/).
_CANDIDATE_PATHS = [
    _ROOT / "data" / "enterprise-attack.json",
    _ROOT / "modul_a3" / "enterprise-attack.json",
]

def _resolve_dataset_path() -> Path:
    for path in _CANDIDATE_PATHS:
        if path.exists():
            return path
    raise FileNotFoundError(
        "enterprise-attack.json tidak ditemukan di "
        f"{[str(p) for p in _CANDIDATE_PATHS]}. "
        "Jalankan: python scripts/download_mitre.py"
    )

@lru_cache(maxsize=1)
#ditambah
def _get_mitre() -> MitreAttackData:
    return MitreAttackData(str(_resolve_dataset_path()))

def get_threat_context(actor_keyword: str) -> str:
    try:
        mitre = _get_mitre()  
        groups = mitre.get_groups()
        hasil = []
        for group in groups:
            name = group.get("name", "")
            aliases = group.get("aliases", [])
            desc = group.get("description", "")
            if (actor_keyword.lower() in name.lower() or
                any(actor_keyword.lower() in a.lower() for a in aliases)):
                hasil.append({
                    "nama": name,
                    "aliases": aliases,
                    "deskripsi": desc[:300]
                })
        if not hasil:
            return f"Tidak ada threat actor ditemukan untuk: {actor_keyword}"
        context = f"=== Threat Actor: '{actor_keyword}' ===\n"
        for h in hasil:
            context += f"Nama     : {h['nama']}\n"
            context += f"Alias    : {', '.join(h['aliases'])}\n"
            context += f"Deskripsi: {h['deskripsi']}...\n"
        return context
    except Exception as e:
        return f"Error: {e}"

def get_malware_context(malware_keyword: str) -> str:
    try:
        mitre = _get_mitre()
        softwares = mitre.get_software()
        hasil = []
        for sw in softwares:
            name = sw.get("name", "")
            desc = sw.get("description", "")
            platforms = sw.get("x_mitre_platforms", [])
            if malware_keyword.lower() in name.lower():
                hasil.append({
                    "nama": name,
                    "platform": platforms,
                    "deskripsi": desc[:300]
                })
        if not hasil:
            return f"Tidak ada malware ditemukan untuk: {malware_keyword}"
        context = f"=== Malware: '{malware_keyword}' ===\n"
        for h in hasil:
            context += f"Nama     : {h['nama']}\n"
            context += f"Platform : {', '.join(h['platform'])}\n"
            context += f"Deskripsi: {h['deskripsi']}...\n"
        return context
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    print(get_threat_context("APT28"))
    print()
    print(get_threat_context("Lazarus"))
    print()
    print(get_malware_context("WannaCry"))
    print()
    print(get_malware_context("Emotet"))
    print()