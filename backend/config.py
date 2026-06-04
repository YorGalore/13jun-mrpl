from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parents[1]


def _clean(value: "str | None") -> "str | None":
    if value is None:
        return None
    value = value.strip()
    return value or None


def _parse_models(raw: "str | None") -> tuple:
    return tuple(m.strip() for m in (raw or "").split(",") if m.strip())


def _int(name: str, default: int) -> int:
    raw = _clean(os.getenv(name))
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"[config] {name}={raw!r} bukan angka, pakai default {default}.")
        return default

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").strip().lower()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
GEMINI_BASE_URL = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_NUM_PREDICT = _int("OLLAMA_NUM_PREDICT", 1024)
OLLAMA_NUM_CTX = _int("OLLAMA_NUM_CTX", 8192)

LLM_TIMEOUT = _int("LLM_TIMEOUT", 120)

_DEFAULT_MODELS = "gemini:gemini-2.5-flash,gemini:gemini-2.0-flash,ollama:llama3.2:3b"
SUPPORTED_MODEL_NAMES = _parse_models(os.getenv("LLM_MODELS", _DEFAULT_MODELS)) or _parse_models(_DEFAULT_MODELS)
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL") or (
    SUPPORTED_MODEL_NAMES[0] if SUPPORTED_MODEL_NAMES else "gemini:gemini-2.5-flash"
)

SPARQL_PUBLIC_ENDPOINT = os.getenv("SEPSES_PUBLIC_ENDPOINT", "https://sepses.ifs.tuwien.ac.at/sparql")
SPARQL_TIMEOUT = _int("SEPSES_SPARQL_TIMEOUT", 20)


def _bool(name: str, default: bool = False) -> bool:
    raw = _clean(os.getenv(name))
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on", "y")


def _first_env(*names: str) -> "str | None":
    """Ambil env var pertama yang terisi dari daftar nama (alias)."""
    for n in names:
        v = _clean(os.getenv(n))
        if v:
            return v
    return None


SPARQL_ENABLE_LOCAL_FALLBACK = (
    _bool("SEPSES_ENABLE_LOCAL_FALLBACK", False) or _bool("SPARQL_ENABLE_LOCAL_FALLBACK", False)
)
SPARQL_LOCAL_ENDPOINT = _first_env("SEPSES_LOCAL_ENDPOINT", "SPARQL_LOCAL_ENDPOINT") or "http://localhost:8890/sparql"
SPARQL_LOCAL_GRAPH = _first_env("SEPSES_LOCAL_GRAPH", "SPARQL_LOCAL_GRAPH") or "http://sepses.local"


MITRE_DATASET_CANDIDATES = (
    _clean(os.getenv("MITRE_DATASET_PATH")) and Path(os.getenv("MITRE_DATASET_PATH")),
    ROOT / "data" / "enterprise-attack.json",
    ROOT / "modul_a3" / "enterprise-attack.json",
)
MITRE_DATASET_CANDIDATES = tuple(p for p in MITRE_DATASET_CANDIDATES if p)


LOGS_FILE = Path(_clean(os.getenv("LOGS_FILE")) or str(ROOT / "data" / "sample_logs.txt"))
CHROMA_DIR = _clean(os.getenv("CHROMA_DIR")) or str(ROOT / "vector_db")

BACKEND_PORT = _int("BACKEND_PORT", 8000)
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")