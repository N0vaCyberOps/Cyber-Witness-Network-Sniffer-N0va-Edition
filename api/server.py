from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.AIThreatAnalyzer import AIThreatAnalyzer
from typing import List

app = FastAPI(
    title="Cyber Witness API",
    version="1.0.0"
)

# Dotychczasowe endpointy (już istniejące)
@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/alerts")
async def get_alerts(limit: int = 100):
    # zakładam, że implementacja istnieje
    return []

@app.post("/rules")
async def add_rule(rule: dict):
    # zakładam, że implementacja istnieje
    return {"status": "rule added"}

# NOWY kod dodany poniżej:

# --------------- NOWY ENDPOINT ANALYZE -------------------

router = APIRouter()
analyzer = AIThreatAnalyzer("models/deepseek.onnx")

class ThreatRequest(BaseModel):
    ip: str
    port: int
    protocol: str  # "TCP", "UDP", "ICMP", "OTHER"

class ThreatResponse(BaseModel):
    threat_score: float

PROTOCOL_MAP = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "OTHER": 3
}

@router.post("/analyze", response_model=ThreatResponse)
async def analyze_threat(request: ThreatRequest):
    protocol_code = PROTOCOL_MAP.get(request.protocol.upper(), 3)
    try:
        score = analyzer.predict(request.ip, request.port, protocol_code)
        return {"threat_score": round(score, 4)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Rejestracja nowego routera:
app.include_router(router)
