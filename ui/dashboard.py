# ui/dashboard.py
import asyncio
from rich.console import Console
from rich.table import Table
from core.AlertCoordinator import AlertCoordinator

class Dashboard:
    def __init__(self, coordinator: AlertCoordinator):
        self.coordinator = coordinator
        self.console = Console()

    async def run(self):
        while True:
            await asyncio.sleep(5)
            self.display_alerts()

    def display_alerts(self):
        table = Table(title="Recent Alerts")
        table.add_column("Time", style="dim")
        table.add_column("Type")
        table.add_column("Message")
        table.add_column("Priority")

        # Wyświetl ostatnie 10 alertów
        for alert in list(self.coordinator.recent_alerts)[-10:]:
            table.add_row(
                str(alert.timestamp),
                alert.alert_type.value,
                alert.message,
                str(alert.priority)
            )

        self.console.clear()
        self.console.print(table)