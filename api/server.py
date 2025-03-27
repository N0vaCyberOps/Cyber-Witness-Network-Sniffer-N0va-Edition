# 📄 Plik: api/server.py (ulepszona wersja)
"""REST API z obsługą CQRS i autoryzacją"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
import os
from pydantic import BaseModel
from core.AlertCoordinator import AlertCoordinator

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def api_key_auth(api_key: str = Depends(API_KEY_HEADER)) -> str:
    if api_key != os.getenv("API_SECRET_KEY"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key"
        )
    return api_key

class Rule(BaseModel):
    name: str
    condition: str
    priority: str
    type: str

class RuleCommandHandler:
    def __init__(self, traffic_monitor):
        self.traffic_monitor = traffic_monitor

    async def handle_add_rule(self, rule: dict) -> dict:
        try:
            validated = self.traffic_monitor._validate_rule(rule)
            self.traffic_monitor.rules.append(validated)
            return {"status": "Rule added"}
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

def create_app(coordinator: AlertCoordinator, rule_handler: RuleCommandHandler) -> FastAPI:
    app = FastAPI(
        title="Cyber Witness API",
        version="1.0.0",
        docs_url="/docs" if os.getenv("ENV") == "dev" else None
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    @app.get("/alerts", dependencies=[Depends(api_key_auth)])
    async def get_alerts(limit: int = 100):
        alerts = [
            {
                "type": alert.alert_type.value,
                "message": alert.message,
                **alert.payload
            }
            for alert in list(coordinator.recent_alerts)[-limit:]
        ]
        return JSONResponse(content={"alerts": alerts})

    @app.post("/rules", dependencies=[Depends(api_key_auth)])
    async def add_rule(rule: Rule):
        return await rule_handler.handle_add_rule(rule.dict())

    return app