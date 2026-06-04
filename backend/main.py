from __future__ import annotations
import traceback
from typing import Any, Dict, List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import DEFAULT_MODEL, FRONTEND_ORIGINS, SUPPORTED_MODEL_NAMES
from backend.pipeline.orchestrator import answer, compare

app = FastAPI(title="SEPSES CSKG Chatbot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


class HistoryItem(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    mode: str = "threat_intelligence"  # threat_intelligence | log_analysis | combined
    sessionId: Optional[str] = None
    history: List[HistoryItem] = []
    model: Optional[str] = None


class RDFTriple(BaseModel):
    subject: str
    predicate: str
    object: str
    source: Optional[str] = None


class ChatResponse(BaseModel):
    message: str
    triples: List[RDFTriple] = []
    llmUsed: Optional[str] = None
    sources: List[str] = []
    method: Optional[str] = None
    sparql: Optional[str] = None


class CompareRequest(BaseModel):
    message: str
    mode: str = "threat_intelligence"
    sessionId: Optional[str] = None
    history: List[HistoryItem] = []
    models: Optional[List[str]] = None


class CompareAnswer(BaseModel):
    model: str
    llmUsed: Optional[str] = None
    message: str
    ok: bool = True
    error: Optional[str] = None
    latencySec: Optional[float] = None


class CompareResponse(BaseModel):
    question: str
    mode: str
    answers: List[CompareAnswer] = []
    triples: List[RDFTriple] = []
    sources: List[str] = []
    method: Optional[str] = None
    sparql: Optional[str] = None


@app.get("/")
def root() -> Dict[str, str]:
    return {"service": "SEPSES CSKG Chatbot API", "docs": "/docs"}


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/models")
def models() -> Dict[str, Any]:
    return {"models": list(SUPPORTED_MODEL_NAMES), "default": DEFAULT_MODEL}


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> Dict[str, Any]:
    try:
        return answer(
            req.message,
            mode=req.mode,
            model=req.model or DEFAULT_MODEL,
            history=[h.model_dump() for h in req.history],
        )
    except Exception as e:  # jaring pengaman: jangan balas 500 mentah ke UI
        traceback.print_exc()
        return {
            "message": f"⚠️ Gagal memproses permintaan: {e}",
            "triples": [],
            "llmUsed": req.model or DEFAULT_MODEL,
            "sources": [],
            "method": None,
            "sparql": None,
        }

@app.post("/api/compare", response_model=CompareResponse)
def compare_models(req: CompareRequest) -> Dict[str, Any]:
    try:
        return compare(
            req.message,
            models=req.models or list(SUPPORTED_MODEL_NAMES),
            mode=req.mode,
            history=[h.model_dump() for h in req.history],
        )
    except Exception as e:  
        traceback.print_exc()
        return {
            "question": req.message,
            "mode": req.mode,
            "answers": [],
            "triples": [],
            "sources": [],
            "method": None,
            "sparql": None,
        }