#!/usr/bin/env python3
"""Cyber Witness: Network Sniffer – N0va Edition"""
import asyncio
import logging
from configparser import ConfigParser
from pathlib import Path
from rich.logging import RichHandler

from core.AlertCoordinator import AlertCoordinator
from core.AdvancedTrafficMonitor import AdvancedTrafficMonitor
from core.errors import ConfigurationError
from core.exporters import ElasticsearchExporter
from network.monitoring import NetworkMonitor
from ui.dashboard import Dashboard
from api.server import create_app, RuleCommandHandler
from fastapi import FastAPI
import uvicorn

CONFIG_PATH = Path("config/config.ini")
RULES_PATH = Path("config/rules.json")

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

def load_config(path: Path) -> ConfigParser:
    if not path.exists():
        raise ConfigurationError(f"Missing config file at {path}")
    config = ConfigParser()
    config.read(path)
    return config

async def main() -> None:
    setup_logging()
    logger = logging.getLogger("CyberWitness")

    config = load_config(CONFIG_PATH)
    interface = config["network"].get("interface", "eth0")
    promiscuous = config["network"].getboolean("promiscuous", True)
    es_url = config["export"].get("elasticsearch_url", "http://localhost:9200")
    model_path = config["ai"].get("onnx_model_path", "models/deepseek.onnx")

    alert_coordinator = AlertCoordinator(mode=config["general"].get("mode", "LiveThreat"))
    exporter = ElasticsearchExporter([es_url])
    network_monitor = NetworkMonitor(interface=interface, promiscuous=promiscuous)
    traffic_monitor = AdvancedTrafficMonitor(
        network_monitor=network_monitor,
        alert_coordinator=alert_coordinator,
        rules_path=RULES_PATH,
        ai_model_path=model_path,
        exporter=exporter
    )
    dashboard = Dashboard(alert_coordinator)
    api_app: FastAPI = create_app(alert_coordinator, RuleCommandHandler(traffic_monitor))

    tasks = [
        asyncio.create_task(network_monitor.start_capture(traffic_monitor.analyze_packet)),
        asyncio.create_task(alert_coordinator.process_alerts()),
        asyncio.create_task(dashboard.run()),
    ]

    uvicorn_config = uvicorn.Config(api_app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(uvicorn_config)
    tasks.append(asyncio.create_task(server.serve()))

    try:
        await asyncio.gather(*tasks)
    finally:
        await exporter.close()
        await network_monitor.stop_capture()

if __name__ == "__main__":
    asyncio.run(main())