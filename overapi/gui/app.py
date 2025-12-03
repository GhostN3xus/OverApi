from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Log, ProgressBar, Tree, TabbedContent, TabPane
from textual.containers import Container, Horizontal, Vertical
from textual import on
from overapi.core.context import ScanContext, ScanStatus
import threading
import time

class OverApiApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    .status-bar {
        height: 3;
        dock: top;
        background: $primary;
        color: $text;
        content-align: center middle;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "generate_report", "Export Report"),
    ]

    def __init__(self, orchestrator):
        super().__init__()
        self.orchestrator = orchestrator
        self.scan_thread = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(f"Target: {self.orchestrator.config.url}", classes="status-bar"),
            ProgressBar(id="scan_progress", total=100),
            TabbedContent(
                TabPane("Live Log", Log(id="log")),
                TabPane("Vulnerabilities", Tree("Vulnerabilities", id="vuln_tree")),
                TabPane("Endpoints", Tree("Endpoints", id="endpoint_tree")),
            )
        )
        yield Footer()

    def on_mount(self) -> None:
        self.log_widget = self.query_one("#log", Log)
        self.progress_bar = self.query_one("#scan_progress", ProgressBar)
        self.vuln_tree = self.query_one("#vuln_tree", Tree)
        self.endpoint_tree = self.query_one("#endpoint_tree", Tree)

        # Start scan in background
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.start()

        # Start UI updater
        self.set_interval(0.5, self.update_ui)

    def run_scan(self):
        self.orchestrator.scan()

    def update_ui(self):
        context = self.orchestrator.context

        # Update progress (fake based on status for now or need better metrics)
        if context.status == ScanStatus.COMPLETED:
            self.progress_bar.update(progress=100)
        elif context.status == ScanStatus.RUNNING:
            self.progress_bar.advance(1) # Simple animation

        # Update endpoints
        self.endpoint_tree.root.expand()
        for ep in context.endpoints:
            # Check if node exists, if not add
            # Simplified: Clear and rebuild is expensive, ideally check existence
            pass

        # We can pipe logger output to self.log_widget if we redirect it

    def action_generate_report(self):
        # Trigger report generation
        self.notify("Generating report...")
