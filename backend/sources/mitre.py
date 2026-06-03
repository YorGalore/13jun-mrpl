"""
GATEWAY 2 — MITRE ATT&CK (SELALU file lokal enterprise-attack.json).

Satu-satunya pintu ke data threat actor / malware / teknik. Eks modul_threat.py.
TIDAK menyentuh SEPSES sama sekali. Hanya bergantung pada backend.config & backend.patterns.

API publik: threat_context(), malware_context(), technique_context().
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from mitreattack.stix20 import MitreAttackData

from backend.config import MITRE_DATASET_CANDIDATES
from backend.patterns import MITRE_GENERAL_KEYWORDS


def _resolve_dataset() -> Path:
    for path in MITRE_DATASET_CANDIDATES:
        if path and Path(path).exists():
            return Path(path)
    raise FileNotFoundError(
        "enterprise-attack.json tidak ditemukan di "
        f"{[str(p) for p in MITRE_DATASET_CANDIDATES]}. "
        "Jalankan: python scripts/download_mitre.py"
    )


@lru_cache(maxsize=1)
def _mitre() -> MitreAttackData:
    """Muat dataset sekali saja (di-cache)."""
    return MitreAttackData(str(_resolve_dataset()))


def threat_context(keyword: str) -> str:
    """Profil threat actor berdasarkan nama/alias."""
    try:
        groups = _mitre().get_groups()
    except Exception as e:
        return f"Error membaca dataset MITRE: {e}"

    k = (keyword or "").lower()
    found = [
        g for g in groups
        if k in (g.get("name", "") or "").lower()
        or any(k in (a or "").lower() for a in g.get("aliases", []) or [])
    ]
    if not found:
        return f"Tidak ada threat actor ditemukan untuk: {keyword}"

    out = f"=== Threat Actor: '{keyword}' ===\n"
    for g in found:
        out += f"Nama     : {g.get('name', '')}\n"
        out += f"Alias    : {', '.join(g.get('aliases', []) or [])}\n"
        out += f"Deskripsi: {(g.get('description', '') or '')[:300]}...\n"
    return out


def malware_context(keyword: str) -> str:
    """Profil malware/software berdasarkan nama."""
    try:
        softwares = _mitre().get_software()
    except Exception as e:
        return f"Error membaca dataset MITRE: {e}"

    k = (keyword or "").lower()
    found = [s for s in softwares if k in (s.get("name", "") or "").lower()]
    if not found:
        return f"Tidak ada malware ditemukan untuk: {keyword}"

    out = f"=== Malware: '{keyword}' ===\n"
    for s in found:
        out += f"Nama     : {s.get('name', '')}\n"
        out += f"Platform : {', '.join(s.get('x_mitre_platforms', []) or [])}\n"
        out += f"Deskripsi: {(s.get('description', '') or '')[:300]}...\n"
    return out


def _attack_id(obj) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "") or ""
    return ""


def _tactics(obj) -> List[str]:
    names = []
    for phase in obj.get("kill_chain_phases", []) or []:
        if phase.get("kill_chain_name") == "mitre-attack":
            names.append((phase.get("phase_name", "") or "").replace("-", " "))
    return [n for n in names if n]


def technique_context(query: str, max_results: int = 6) -> str:
    """Cari teknik ATT&CK yang cocok dengan kata kunci pada pertanyaan."""
    q = (query or "").lower().strip()
    if not q:
        return ""
    try:
        techniques = _mitre().get_techniques(include_subtechniques=True)
    except Exception as e:
        return f"Error membaca dataset MITRE: {e}"

    terms = [kw for kw in MITRE_GENERAL_KEYWORDS if kw in q] or [q]
    found, seen = [], set()
    for t in techniques:
        if t.get("revoked") or t.get("x_mitre_deprecated"):
            continue
        name = t.get("name", "") or ""
        desc = t.get("description", "") or ""
        tactics = _tactics(t)
        blob = f"{name} {' '.join(tactics)} {desc}".lower()
        if not any(term in blob for term in terms):
            continue
        tid = _attack_id(t)
        key = tid or name
        if key in seen:
            continue
        seen.add(key)
        found.append({"id": tid, "name": name, "tactics": tactics, "desc": desc[:300]})
        if len(found) >= max_results:
            break

    if not found:
        return f"Tidak ada teknik MITRE ATT&CK ditemukan untuk: {query}"

    out = f"=== MITRE ATT&CK Techniques: '{', '.join(terms)}' ===\n"
    for f in found:
        prefix = f"[{f['id']}] " if f["id"] else ""
        out += f"Teknik   : {prefix}{f['name']}\n"
        if f["tactics"]:
            out += f"Tactic   : {', '.join(f['tactics'])}\n"
        if f["desc"]:
            out += f"Deskripsi: {f['desc']}...\n"
        out += "\n"
    return out.rstrip() + "\n"