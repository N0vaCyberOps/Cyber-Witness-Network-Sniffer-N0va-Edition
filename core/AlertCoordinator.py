# 📄 Plik: core/AlertCoordinator.py (ulepszona wersja)
"""Asynchroniczny system alertów z kontrolą przepływu"""
import asyncio
import time
import logging
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Optional, Dict, Any, Callable, List
from pydantic import BaseModel, ValidationError
from collections import deque

class AlertType(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

class AlertPriority(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

@dataclass(order=True)
class QueuedAlert:
    priority: int
    timestamp: float = field(compare=False)
    alert_type: AlertType = field(compare=False)
    message: str = field(compare=False)
    payload: Dict[str, Any] = field(compare=False)

class AlertSchema(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    packet_size: Optional[int] = None
    metadata: Dict[str, Any] = {}

class AlertCoordinator:
    def __init__(self, mode: str = "LiveThreat", max_queue_size: int = 10000):
        self.mode = mode
        self.alert_queue = asyncio.PriorityQueue(maxsize=max_queue_size)
        self.handlers: List[Callable[[QueuedAlert], None]] = []
        self._rate_limiter = deque(maxlen=1000)
        self.recent_alerts = deque(maxlen=1000)
        self._modes = {"Silent", "Forensic", "LiveThreat"}
        
        if mode not in self._modes:
            raise ValueError(f"Invalid mode: {mode}")

    async def add_alert(
        self,
        alert_type: AlertType,
        message: str,
        priority: AlertPriority,
        raw_payload: Dict[str, Any]
    ) -> bool:
        """Dodaj alert z kontrolą przepustowości i walidacją"""
        if time.monotonic() - self._rate_limiter[0] < 0.01 and len(self._rate_limiter) >= 1000:
            logging.warning("Alert rate limit exceeded")
            return False
            
        try:
            validated = AlertSchema(**raw_payload).dict()
            alert = QueuedAlert(
                priority=priority.value,
                alert_type=alert_type,
                message=message[:255],
                timestamp=time.time(),
                payload=validated
            )
            await self.alert_queue.put(alert)
            self.recent_alerts.append(alert)
            self._rate_limiter.append(time.monotonic())
            return True
        except ValidationError as e:
            logging.error(f"Invalid alert payload: {e.errors()}")
            return False

    async def process_alerts(self) -> None:
        """Przetwarzaj alerty z uwzględnieniem trybu operacyjnego"""
        while True:
            alert = await self.alert_queue.get()
            try:
                if self.mode == "Silent":
                    continue
                
                if self.mode == "Forensic":
                    self._log_forensic(alert)
                
                if self.mode == "LiveThreat":
                    await self._dispatch_alert(alert)
            finally:
                self.alert_queue.task_done()

    async def _dispatch_alert(self, alert: QueuedAlert) -> None:
        """Rozsyłaj alerty do zarejestrowanych handlerów"""
        for handler in self.handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logging.error(f"Handler failure: {str(e)}", exc_info=True)

    def _log_forensic(self, alert: QueuedAlert) -> None:
        """Pełne logowanie forenzyczne"""
        logging.info(
            f"[Forensic] {alert.message}\n"
            f"Payload: {alert.payload}\n"
            f"Timestamp: {alert.timestamp}"
        )

    def register_handler(self, handler: Callable[[QueuedAlert], None]) -> None:
        """Rejestracja handlerów alertów"""
        self.handlers.append(handler)