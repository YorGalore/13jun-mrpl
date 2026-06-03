from __future__ import annotations

from typing import Optional, Tuple

from backend.config import (
    DEFAULT_MODEL,
    GEMINI_API_KEY,
    GEMINI_BASE_URL,
    LLM_PROVIDER,
    LLM_TIMEOUT,
    OLLAMA_BASE_URL,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
    SUPPORTED_MODEL_NAMES,
)

_KNOWN_PROVIDERS = {"gemini", "ollama"}


def _split_provider(model_name: str) -> Tuple[Optional[str], str]:
    """('gemini'|'ollama'|None, model_id). split(':',1) menjaga ':' di dalam id (mis. llama3.2:3b)."""
    if ":" in model_name:
        head, tail = model_name.split(":", 1)
        if head.lower() in _KNOWN_PROVIDERS and tail:
            return head.lower(), tail
    return None, model_name


def _normalize_ollama_base_url(url: str) -> str:
    url = (url or "").rstrip("/")
    if url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url or "http://localhost:11434"


def _build_gemini(model_id: str):
    if not GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY belum diset. Dapatkan dari https://aistudio.google.com/apikey "
            "lalu isi di .env, atau pilih model 'ollama:...' di dropdown."
        )
    try:
        from langchain_openai import ChatOpenAI  # pakai SDK openai di dalamnya, seperti kel5
    except ImportError as e:
        raise RuntimeError(
            "Paket 'langchain-openai' belum terpasang. Jalankan: pip install langchain-openai"
        ) from e

    return ChatOpenAI(
        model=model_id,
        api_key=GEMINI_API_KEY,
        base_url=GEMINI_BASE_URL,  # endpoint OpenAI-compatible milik Gemini
        temperature=0,
        timeout=LLM_TIMEOUT,
        max_retries=3,
    )


def _build_ollama(model_id: str):
    try:
        from langchain_ollama import ChatOllama  # impor lazy: hanya saat Ollama dipakai
    except ImportError as e:
        raise RuntimeError(
            "Paket 'langchain-ollama' belum terpasang. Jalankan: pip install langchain-ollama "
            "(atau pilih model 'gemini:...' di dropdown)."
        ) from e
    return ChatOllama(
        model=model_id,
        temperature=0,
        base_url=_normalize_ollama_base_url(OLLAMA_BASE_URL),
        num_predict=OLLAMA_NUM_PREDICT,
        num_ctx=OLLAMA_NUM_CTX,
        client_kwargs={"timeout": LLM_TIMEOUT},
    )


def _build(provider: str, model_id: str):
    if provider == "gemini":
        return _build_gemini(model_id)
    if provider == "ollama":
        return _build_ollama(model_id)
    raise ValueError(f"Provider LLM tidak dikenal: {provider}")


class LLMProvider:
    @staticmethod
    def get_model(model_name: str = DEFAULT_MODEL):
        name = (model_name or DEFAULT_MODEL).strip()
        provider, model_id = _split_provider(name)
        if provider is None:
            provider = LLM_PROVIDER
        return _build(provider, model_id)


SUPPORTED_MODELS = {
    name: {"provider": (_split_provider(name)[0] or LLM_PROVIDER)}
    for name in SUPPORTED_MODEL_NAMES
}