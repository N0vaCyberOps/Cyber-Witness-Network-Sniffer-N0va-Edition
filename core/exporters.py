# 📄 Plik: core/exporters.py (ulepszona wersja)
"""Asynchroniczny eksport danych z fallbackiem"""
import aiofiles
import json
from elasticsearch import AsyncElasticsearch, TransportError
from typing import Optional

class ElasticsearchExporter:
    def __init__(self, hosts: list, index: str = "cyberwitness-alerts"):
        self.client = AsyncElasticsearch(hosts)
        self.index = index
        self._fallback_file = "alerts_fallback.ndjson"

    async def export_alert(self, alert: dict) -> bool:
        """Eksportuj z obsługą błędów i fallbackiem"""
        try:
            await self.client.index(
                index=self.index,
                document=alert,
                timeout="500ms"
            )
            return True
        except (TransportError, ConnectionError) as e:
            logging.warning(f"ES export failed: {e}, using fallback")
            return await self._write_to_fallback(alert)
        except Exception as e:
            logging.error(f"Unexpected export error: {e}")
            return False

    async def _write_to_fallback(self, alert: dict) -> bool:
        """Zapisz alert do pliku w formacie NDJSON"""
        try:
            async with aiofiles.open(self._fallback_file, "a") as f:
                await f.write(f"{json.dumps(alert)}\n")
            return True
        except IOError as e:
            logging.error(f"Fallback write failed: {e}")
            return False

    async def close(self) -> None:
        """Zamknij połączenia"""
        await self.client.close()