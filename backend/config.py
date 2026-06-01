import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-4o-mini")
SUPPORTED_MODEL_NAMES = ("gpt-4o-mini", "deepseek-chat")
SPARQL_PUBLIC_ENDPOINT = os.getenv("SEPSES_PUBLIC_ENDPOINT", "https://sepses.ifs.tuwien.ac.at/sparql")
SPARQL_LOCAL_ENDPOINT = os.getenv("SEPSES_LOCAL_ENDPOINT", "http://localhost:8890/sparql")
def _clean_graph(value: "str | None") -> "str | None":
    if value is None:
        return None
    value = value.strip()
    return value or None
DEFAULT_GRAPH = _clean_graph(os.getenv("SEPSES_DEFAULT_GRAPH", ""))
LOCAL_GRAPH = _clean_graph(os.getenv("SEPSES_LOCAL_GRAPH", "http://sepses.local"))
ENABLE_LOCAL_FALLBACK = os.getenv("SEPSES_ENABLE_LOCAL_FALLBACK", "1").strip() not in (
    "0",
    "false",
    "False",
    "",
)
SPARQL_TIMEOUT = int(os.getenv("SEPSES_SPARQL_TIMEOUT", "60"))
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))
