from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Input, DataTable, Select
from textual.containers import Vertical, Horizontal
import json
import os
import constants_textual as constant
import main
import asyncio
from functools import partial

class PipelineInputs(App):

    BINDINGS = constant.BINDINGS
    TITLE = constant.TITLE
    SUB_TITLE = constant.SUB_TITLE

    def __init__(self):
        super().__init__()
        self.paths = {"pcap": None, "ndpi": None, "output": None}
        self.left_panel = None
        self.right_panel = None
        self.statistics_select = None
        self.flows_select = None
        self.current_stats_file = "tmp/initialization.txt"
        self.current_flow_file = "tmp/filtered_flows.json"
    
    async def run_main_in_background(self):
        loop = asyncio.get_running_loop()
        # esegue main.main in un thread separato, così non blocca la UI
        await loop.run_in_executor(None, partial(main.main_pipeline, self.paths["pcap"], self.paths["ndpi"], self.paths["output"]))

    def compose(self) -> ComposeResult:
        
        yield Header(show_clock=True)
        yield Static("Please provide the required paths and press Enter after each one ...", id="banner")

        pcap_input = Input(placeholder="Enter PCAP file path and press Enter", id="pcap_input")
        pcap_input.styles.padding = (0, 5)
        pcap_input.styles.margin = (10, 20, 1, 20)
        pcap_input.styles.min_height = 1
        pcap_input.styles.height = "auto"
        yield pcap_input

        ndpi_input = Input(placeholder="Enter nDPI folder path and press Enter", id="ndpi_input")
        ndpi_input.styles.padding = (0, 5)
        ndpi_input.styles.margin = (1, 20)
        ndpi_input.styles.min_height = 1
        ndpi_input.styles.height = "auto"
        yield ndpi_input

        output_input = Input(placeholder="Enter output folder path and press Enter", id="output_input")
        output_input.styles.padding = (0, 5)
        output_input.styles.margin = (1, 20)
        output_input.styles.min_height = 1
        output_input.styles.height = "auto"
        yield output_input

        yield Vertical(id="main_panel")
        yield Footer()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Salva il percorso inserito
        if event.input.id == "pcap_input":
            self.paths["pcap"] = event.value.strip()
            self.notify(f"PCAP file set: {event.value.strip()}", severity="information")
        elif event.input.id == "ndpi_input":
            self.paths["ndpi"] = event.value.strip()
            self.notify(f"nDPI directory set: {event.value.strip()}", severity="information")
        elif event.input.id == "output_input":
            self.paths["output"] = event.value.strip()
            self.notify(f"Output folder set: {event.value.strip()}", severity="information")

        # Se tutti e tre i percorsi sono presenti
        if all(self.paths.values()):
            # Rimuovi input e banner
            self.query_one("#pcap_input").remove()
            self.query_one("#ndpi_input").remove()
            self.query_one("#output_input").remove()
            self.query_one("#banner").remove()

            # Mostra pannelli
            self.display_panels()

    def display_panels(self):

        # Lancia main.main in background (thread-safe)
        asyncio.create_task(self.run_main_in_background())
        #main.main_pipeline(self.paths["pcap"], self.paths["ndpi"], self.paths["output"])

        main_container = self.query_one("#main_panel", Vertical)

        select_container = Horizontal(id="select_container")
        
        select_container.styles.padding = (0, 0)
        select_container.styles.margin = (0, 0)
        select_container.styles.min_height = 0
        select_container.styles.height = "auto"

        main_container.mount(select_container)
        self.statistics_select = Select([(title, key) for key, (title, _) in constant.GROUPS["statistics"].items()], id="statistics_select", prompt="Statistics of Flows")
        self.flows_select = Select([(title, key) for key, (title, _) in constant.GROUPS["flows"].items()], id="flows_select", prompt="Flows")

        self.statistics_select.styles.padding = (0, 0)
        self.statistics_select.styles.margin = (1, 10)
        self.statistics_select.styles.min_height = 1
        self.statistics_select.styles.height = "auto"

        self.flows_select.styles.padding = (0, 0)
        self.flows_select.styles.margin = (1, 10)
        self.flows_select.styles.min_height = 1
        self.flows_select.styles.height = "auto"

        select_container.mount(self.statistics_select, self.flows_select)
        # --- Container orizzontale per i pannelli ---

        panels_container = Horizontal(id="panels_container")
        main_container.mount(panels_container)

        self.left_panel = Vertical(Static(self.current_stats_file, id="left_text"))
        #self.left_panel.styles.width = 70
        self.left_panel.styles.margin = (1, 3)
        self.right_panel = Vertical(DataTable(zebra_stripes=True, id="json_table"))
        self.right_panel.styles.margin = (1, 3)
        panels_container.mount(self.left_panel, self.right_panel)

        # Aggiornamento periodico
        self.set_interval(1, self.refresh_panels)

    def refresh_panels(self):

        # --- Aggiornamento pannello sinistro ---
        left_widget = self.left_panel.query_one("#left_text", Static)
        stats_file = getattr(self, "current_stats_file", "tmp/initialization.txt")

        if os.path.exists(stats_file) and os.path.getsize(stats_file) > 0:
            try:
                with open(stats_file, "r", encoding="utf-8") as f:
                    stats_content = f.read()
            except Exception:
                stats_content = "⚠ Error reading file"
        else:
            stats_content = "⚠ File not found or empty"

        # Aggiorna solo se il contenuto è cambiato
        if getattr(self, "_last_stats_content", None) != stats_content:
            left_widget.update(stats_content)
            self._last_stats_content = stats_content

        # Aggiorna pannello destro (tabella JSON)
        table = self.right_panel.query_one("#json_table", DataTable)
        table.styles.max_height = 30   # 30 righe circa

        json_file = getattr(self, "current_flow_file", "tmp/filtered_flows.json")
        if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    flows = json.load(f)
            except json.JSONDecodeError:
                flows = []
        else:
            flows = []

        # Se i dati non sono cambiati, non toccare la tabella
        if getattr(self, "_last_flows", None) == flows:
            return  
        self._last_flows = flows

        table.clear()
        if not table.columns:
            for col in ["Protocol", "Source IP", "Destination IP", "SNI/URL", "Risk"]:
                table.add_column(col)

        if flows:
            for flow in flows:
                proto = flow.get("proto_field", "N/A")
                src = flow.get("ip_source", "N/A")
                dst = flow.get("ip_destination", "N/A")
                sni = flow.get("sni") or flow.get("url", "N/A")
                risk = flow.get("risk", "None")
                table.add_row(proto, src, dst, sni, risk)
        else:
            table.add_row("N/A", "N/A", "N/A", "No data", "None")

    def on_select_changed(self, event: Select.Changed) -> None:
        key = event.value
        select_id = event.select.id

        if select_id == "statistics_select":
            # Prendi il path del file selezionato per il pannello destro
            _, file_path = constant.GROUPS["statistics"][key]
            self.current_stats_file = file_path
            self.update_left_panel(file_path)

        elif select_id == "flows_select":
            # Prendi il path del file selezionato per il pannello sinistro
            _, file_path = constant.GROUPS["flows"][key]
            self.current_flow_file = file_path  # aggiorna il file corrente
            self.update_right_panel(file_path)

    def update_left_panel(self, file_path):
        left_widget = self.left_panel.query_one("#left_text", Static)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                left_widget.update(f.read())
        else:
            left_widget.update("⚠ File not found or empty")

    def update_right_panel(self, file_path):
        table = self.right_panel.query_one("#json_table", DataTable)
        table.styles.max_height = 30   # 30 righe circa
        table.clear()
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    flows = json.load(f)
            except json.JSONDecodeError:
                flows = []
        else:
            flows = []

        columns = ["Protocol", "Source IP", "Destination IP", "SNI/URL", "Risk"]
        if not table.columns:
            for col in columns:
                table.add_column(col)

        if flows:
            for flow in flows:
                proto = flow.get("proto_field", "N/A")
                src = flow.get("ip_source", "N/A")
                dst = flow.get("ip_destination", "N/A")
                sni = flow.get("sni") or flow.get("url", "N/A")
                risk = flow.get("risk", "None")
                table.add_row(proto, src, dst, sni, risk)
        else:
            table.add_row("N/A", "N/A", "N/A", "No data", "None")

if __name__ == "__main__":
    PipelineInputs().run()
