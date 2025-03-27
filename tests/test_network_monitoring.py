# 📄 Plik: tests/test_network_monitoring.py (ulepszona wersja)
"""Testy wydajnościowe i brzegowe"""
import pytest
from unittest.mock import AsyncMock
from network.monitoring import NetworkMonitor

@pytest.mark.asyncio
async def test_high_throughput():
    """Test wydajności bufora pakietów"""
    monitor = NetworkMonitor(buffer_size=1000)
    mock_callback = AsyncMock()
    
    await monitor.start_capture(mock_callback)
    
    # Generuj 10k pakietów testowych
    for _ in range(10000):
        monitor._buffer_packet("test_packet", mock_callback)
    
    await asyncio.sleep(1)
    await monitor.stop_capture()
    
    assert mock_callback.call_count <= 1000  # Weryfikacja kontroli przepływu

@pytest.mark.asyncio
async def test_invalid_interface():
    """Test obsługi błędnego interfejsu"""
    monitor = NetworkMonitor(interface="invalid0")
    
    with pytest.raises(Exception):
        await monitor.start_capture(lambda x: x)
    
    await monitor.stop_capture()