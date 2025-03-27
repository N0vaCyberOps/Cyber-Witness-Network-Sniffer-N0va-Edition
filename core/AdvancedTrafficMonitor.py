# core/AdvancedTrafficMonitor.py
import json
from typing import List, Dict
from scapy.packet import Packet
from core.AlertCoordinator import AlertCoordinator, AlertType, AlertPriority
from core.AIThreatAnalyzer import AIThreatAnalyzer
from simpleeval import simple_eval

class AdvancedTrafficMonitor:
    def __init__(self, network_monitor, alert_coordinator: AlertCoordinator, rules_path: str, ai_model_path: str, exporter):
        self.network_monitor = network_monitor
        self.alert_coordinator = alert_coordinator
        self.rules = self.load_rules(rules_path)
        self.ai_analyzer = AIThreatAnalyzer(ai_model_path)
        self.exporter = exporter

    def load_rules(self, path: str) -> List[Dict]:
        with open(path, 'r') as f:
            rules = json.load(f)
        return rules

    async def analyze_packet(self, packet: Packet):
        # Wyodrębnij istotne informacje z pakietu
        pkt_data = {
            'src_ip': packet[0][1].src if hasattr(packet[0][1], 'src') else None,
            'dst_ip': packet[0][1].dst if hasattr(packet[0][1], 'dst') else None,
            'protocol': packet[0][1].proto if hasattr(packet[0][1], 'proto') else None,
            'packet_size': len(packet),
            'dst_port': getattr(packet[0][1], 'dport', None)
        }
        # Sprawdź reguły
        for rule in self.rules:
            if self._evaluate_rule(rule['condition'], pkt_data):
                await self.alert_coordinator.add_alert(
                    alert_type=AlertType(rule['type']),
                    message=rule['name'],
                    priority=AlertPriority[rule['priority']],
                    raw_payload=pkt_data
                )

        # Opcjonalnie, użyj AI do analizy
        if self._should_use_ai(pkt_data):
            ai_result = await self.ai_analyzer.analyze(pkt_data)
            if ai_result.get('threat_level', 0) > 0.5:  # Próg przykład
                await self.alert_coordinator.add_alert(
                    alert_type=AlertType.CRITICAL,
                    message="AI detected threat",
                    priority=AlertPriority.HIGH,
                    raw_payload={**pkt_data, 'ai_result': ai_result}
                )

    def _evaluate_rule(self, condition: str, pkt_data: Dict) -> bool:
        try:
            return simple_eval(condition, names={'pkt': pkt_data})
        except Exception as e:
            logging.error(f"Rule evaluation error: {e}")
            return False

    def _should_use_ai(self, pkt_data: Dict) -> bool:
        # Logika, kiedy używać AI
        return True  # Dla przykładu