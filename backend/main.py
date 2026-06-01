from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import DEFAULT_MODEL
from backend.pipeline.orchestrator import answer

app = FastAPI(title="SEPSES CSKG Chatbot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class HistoryItem(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    mode: str = "threat_intelligence"          # threat_intelligence | log_analysis | combined
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
    method: Optional[str] = None      # regex | llm | None  (explainability)
    sparql: Optional[str] = None      # query SPARQL yang dipakai (jika ada)


@app.get("/")
def root() -> Dict[str, str]:
    return {"service": "SEPSES CSKG Chatbot API", "docs": "/docs"}


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> Dict[str, Any]:
    return answer(req.message, mode=req.mode, model=req.model or DEFAULT_MODEL,history=[h.model_dump() for h in req.history],)