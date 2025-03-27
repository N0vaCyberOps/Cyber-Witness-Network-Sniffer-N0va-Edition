# 📄 Plik: network/monitoring.py (ulepszona wersja)
"""Asynchroniczne przechwytywanie pakietów z kontrolą przepustowości"""
from scapy.all import AsyncSniffer
from scapy.packet import Packet
from typing import Callable, Optional
import asyncio

class NetworkMonitor:
    def __init__(self, interface: str = "eth0", promiscuous: bool = True, buffer_size: int = 10000):
        self.interface = interface
        self.promiscuous = promiscuous
        self.sniffer: Optional[AsyncSniffer] = None
        self._packet_buffer = asyncio.Queue(maxsize=buffer_size)
        self._stop_event = asyncio.Event()

    async def start_capture(self, callback: Callable[[Packet], None]) -> None:
        """Rozpocznij przechwytywanie z buforowaniem"""
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=lambda pkt: self._buffer_packet(pkt, callback),
            promisc=self.promiscuous,
            store=False
        )
        self.sniffer.start()
        asyncio.create_task(self._process_buffer())

    def _buffer_packet(self, packet: Packet, callback: Callable) -> None:
        """Buforuj pakiety z kontrolą przeciążenia"""
        try:
            self._packet_buffer.put_nowait((packet, callback))
        except asyncio.QueueFull:
            logging.warning("Packet buffer overflow - dropping packets")

    async def _process_buffer(self) -> None:
        """Asynchroniczne przetwarzanie bufora pakietów"""
        while not self._stop_event.is_set():
            packet, callback = await self._packet_buffer.get()
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(packet)
                else:
                    callback(packet)
            except Exception as e:
                logging.error(f"Packet processing error: {e}")
            finally:
                self._packet_buffer.task_done()

    async def stop_capture(self) -> None:
        """Bezpieczne zatrzymanie przechwytywania"""
        self._stop_event.set()
        if self.sniffer:
            self.sniffer.stop()
            await asyncio.wait_for(
                self.sniffer.join(),
                timeout=5,
                loop=asyncio.get_event_loop()
            )
        await self._packet_buffer.join()