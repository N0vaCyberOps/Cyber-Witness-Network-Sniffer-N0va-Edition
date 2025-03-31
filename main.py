#!/usr/bin/env python3
"""Cyber Witness: Network Sniffer – N0va Edition"""
import asyncio
import logging
from configparser import ConfigParser
from pathlib import Path
from typing import List, Optional

# Third-party imports
from fastapi import FastAPI
from rich.logging import RichHandler
import uvicorn

# Local imports
from core.AlertCoordinator import AlertCoordinator
from core.AdvancedTrafficMonitor import AdvancedTrafficMonitor
from core.errors import ConfigurationError
from core.exporters import ElasticsearchExporter
from network.monitoring import NetworkMonitor
from ui.dashboard import Dashboard
from api.server import create_app, RuleCommandHandler

# Constants
CONFIG_PATH = Path("config/config.ini")
RULES_PATH = Path("config/rules.json")
DEFAULT_INTERFACE = "eth0"
DEFAULT_ES_URL = "http://localhost:9200"
DEFAULT_MODEL_PATH = "models/deepseek.onnx"
DEFAULT_MODE = "LiveThreat"
API_HOST = "0.0.0.0"
API_PORT = 8000


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the application logger.
    
    Args:
        level: The logging level to use
        
    Returns:
        The configured logger instance
    """
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    return logging.getLogger("CyberWitness")


def load_config(path: Path) -> ConfigParser:
    """Load configuration from the specified path.
    
    Args:
        path: Path to the configuration file
        
    Returns:
        Loaded configuration
        
    Raises:
        ConfigurationError: If the configuration file doesn't exist
    """
    if not path.exists():
        raise ConfigurationError(f"Missing config file at {path}")
    
    config = ConfigParser()
    config.read(path)
    return config


async def shutdown_tasks(tasks: List[asyncio.Task], exporter: ElasticsearchExporter, 
                         network_monitor: NetworkMonitor) -> None:
    """Properly shutdown all running tasks and resources.
    
    Args:
        tasks: List of running tasks to cancel
        exporter: Elasticsearch exporter to close
        network_monitor: Network monitor to stop
    """
    for task in tasks:
        if not task.done():
            task.cancel()
    
    await exporter.close()
    await network_monitor.stop_capture()
    
    # Wait for all tasks to complete their cancellation
    await asyncio.gather(*tasks, return_exceptions=True)


async def main() -> None:
    """Main application entry point."""
    logger = setup_logging()
    logger.info("Starting Cyber Witness Network Sniffer – N0va Edition")
    
    try:
        config = load_config(CONFIG_PATH)
        
        # Network configuration
        interface = config["network"].get("interface", DEFAULT_INTERFACE)
        promiscuous = config["network"].getboolean("promiscuous", True)
        
        # Export configuration
        es_url = config["export"].get("elasticsearch_url", DEFAULT_ES_URL)
        
        # AI configuration
        model_path = config["ai"].get("onnx_model_path", DEFAULT_MODEL_PATH)
        
        # General configuration
        mode = config["general"].get("mode", DEFAULT_MODE)
        
        # Initialize components
        alert_coordinator = AlertCoordinator(mode=mode)
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
        api_app: FastAPI = create_app(
            alert_coordinator, 
            RuleCommandHandler(traffic_monitor)
        )

        # Create and start tasks
        tasks = [
            asyncio.create_task(network_monitor.start_capture(traffic_monitor.analyze_packet)),
            asyncio.create_task(alert_coordinator.process_alerts()),
            asyncio.create_task(dashboard.run()),
        ]

        # Configure and start API server
        uvicorn_config = uvicorn.Config(
            api_app, 
            host=API_HOST, 
            port=API_PORT, 
            log_level="info"
        )
        server = uvicorn.Server(uvicorn_config)
        api_task = asyncio.create_task(server.serve())
        tasks.append(api_task)

        logger.info(f"API server running at http://{API_HOST}:{API_PORT}")
        logger.info(f"Monitoring network on interface: {interface}")
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        return
    except asyncio.CancelledError:
        logger.info("Application shutdown requested")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
    finally:
        # Ensure proper cleanup of resources
        if 'tasks' in locals() and 'exporter' in locals() and 'network_monitor' in locals():
            await shutdown_tasks(tasks, exporter, network_monitor)
        
        logger.info("Cyber Witness Network Sniffer shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
