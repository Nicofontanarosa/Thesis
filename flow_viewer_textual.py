
#################################################################
# File: flow_viewer_textual.py - used to run the GUI interface
#################################################################

# libraries from textual
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, LoadingIndicator, Input, DataTable, Select
from textual.containers import Vertical, Horizontal
from textual.containers import VerticalScroll
# standard libraries
import json
import os
import asyncio
from functools import partial
# my files
import constants_textual as constant
import main

class PipelineInputs(App):

    # bindings, title, subtitle come from constants_textual
    BINDINGS = constant.BINDINGS
    TITLE = constant.TITLE
    SUB_TITLE = constant.SUB_TITLE

    def __init__(self):
        super().__init__()
        
        # Default paths
        #self.paths = {"pcap": "pcapng/Glovo_01.pcapng", "ndpi": "None", "output": "test/Glovo/Glovo_01"}
        self.paths = {"pcap": None, "ndpi": None, "output": None}
        self.left_panel = None
        self.right_panel = None
        self.statistics_select = None
        self.flows_select = None

        # currently selected files for left/right panels
        self.current_stats_file = "tmp/initialization.txt"
        self.current_flow_file = "tmp/filtered_flows.json"
    
    async def run_main_in_background(self):

        # run main.main_pipeline asynchronously in a separate thread (UI non-blocking)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, partial(main.main_pipeline, self.paths["pcap"], self.paths["ndpi"], self.paths["output"]))

    def compose(self) -> ComposeResult:

        # build initial UI layout
        yield Header(show_clock=True)
        banner = Static("Please provide the required paths and press Enter after each one ...", id="banner")
        banner.styles.margin = (5, 50, 0, 50)
        banner.styles.width = 80
        banner.styles.border = ("round", "#5AC5FF")
        banner.styles.padding = (1, 3)
        yield banner

        # input for PCAP
        pcap_input = Input(placeholder="Enter PCAP file path and press Enter", id="pcap_input")
        pcap_input.styles.padding = (0, 5)
        pcap_input.styles.margin = (10, 20, 1, 20)
        pcap_input.styles.min_height = 1
        pcap_input.styles.height = "auto"
        yield pcap_input

        # input for nDPI path
        ndpi_input = Input(placeholder="Enter nDPI folder path and press Enter", id="ndpi_input")
        ndpi_input.styles.padding = (0, 5)
        ndpi_input.styles.margin = (1, 20)
        ndpi_input.styles.min_height = 1
        ndpi_input.styles.height = "auto"
        yield ndpi_input

        # input for output folder
        output_input = Input(placeholder="Enter output folder path and press Enter", id="output_input")
        output_input.styles.padding = (0, 5)
        output_input.styles.margin = (1, 20)
        output_input.styles.min_height = 1
        output_input.styles.height = "auto"
        yield output_input

        # empty vertical container for panels
        yield VerticalScroll(id="main_panel")
        yield Footer()

    def on_input_submitted(self, event: Input.Submitted) -> None:

        # save path entered by user
        if event.input.id == "pcap_input":
            #self.paths["pcap"] = "pcapng/Glovo_01.pcapng"
            self.paths["pcap"] = event.value.strip()
            self.notify(f"PCAP file set: {event.value.strip()}", severity="information")
        elif event.input.id == "ndpi_input":
            self.paths["ndpi"] = event.value.strip()
            self.notify(f"nDPI directory set: {event.value.strip()}", severity="information")
        elif event.input.id == "output_input":
            self.paths["output"] = event.value.strip()
            self.notify(f"Output folder set: {event.value.strip()}", severity="information")

        # if all three are provided, remove inputs and show panels
        if all(self.paths.values()):
            self.query_one("#pcap_input").remove()
            self.query_one("#ndpi_input").remove()
            self.query_one("#output_input").remove()
            self.query_one("#banner").remove()
            # Start program
            self.display_panels()

    def display_panels(self):

        # run main() asynchronously in background (thread-safe)
        asyncio.create_task(self.run_main_in_background())

        main_container = self.query_one("#main_panel", VerticalScroll)

        # Dropdowns (statistics / flows)
        select_container = Horizontal(id="select_container")
        select_container.styles.padding = (0, 0)
        select_container.styles.margin = (0, 0)
        select_container.styles.min_height = 0
        select_container.styles.height = "auto"

        main_container.mount(select_container)
        
        self.statistics_select = Select([(title, key) for key, (title, _) in constant.GROUPS["statistics"].items()], id="statistics_select", prompt="Statistics of Flows")
        self.flows_select = Select([(title, key) for key, (title, _) in constant.GROUPS["flows"].items()], id="flows_select", prompt="Flows")

        self.statistics_select.styles.padding = (0, 0)
        self.statistics_select.styles.margin = (1, 5, 1, 5)
        self.statistics_select.styles.min_height = 1
        self.statistics_select.styles.height = "auto"

        self.flows_select.styles.padding = (0, 0)
        self.flows_select.styles.margin = (1, 20, 1, 20)
        self.flows_select.styles.min_height = 1
        self.flows_select.styles.height = "auto"

        select_container.mount(self.statistics_select, self.flows_select)
        # ---------------------

        # left panel (statistics) and right panel (flows table)
        panels_container = Horizontal(id="panels_container")
        main_container.mount(panels_container)

        self.left_panel = VerticalScroll(Static("", id="left_text"))
        self.left_panel.styles.width = 70
        self.left_panel.styles.border = ("round", "#5280FF")
        self.left_panel.styles.margin = (1, 3)
        self.left_panel.styles.padding = (1, 3)

        self.right_panel = VerticalScroll(DataTable(zebra_stripes=True, id="json_table"))
        self.right_panel.styles.border = ("round", "#5280FF")
        self.right_panel.styles.margin = (1, 3)
        self.right_panel.styles.padding = (1, 2)

        panels_container.mount(self.left_panel, self.right_panel)

        # keep track of last contents for updates
        self._last_error_content = None

        # auto refresh every second
        self.set_interval(1, self.refresh_panels)

    def refresh_panels(self):

        # --- Error allert ---
        errors_file = "tmp/errors.txt"
        error_content = None
        if os.path.exists(errors_file) and os.path.getsize(errors_file) > 0:
            with open(errors_file, "r", encoding="utf-8") as f:
                error_content = f.read()

        # notify only if content changed and is not empty
        if error_content and self._last_error_content != error_content:
            self.notify(f"Error: {error_content.strip()}", severity="error")
            self._last_error_content = error_content

        # --- LEFT PANEL: stats file ---
        left_widget = self.left_panel.query_one("#left_text", Static)
        left_widget.styles.text_wrap = "wrap"
        left_widget.styles.text_overflow = "fold"
        stats_file = getattr(self, "current_stats_file", "tmp/initialization.txt")

        if not os.path.exists(stats_file) or os.path.getsize(stats_file) == 0:
            # show loading animation if empty
            if not hasattr(self, "_loading_widget") or self._loading_widget is None:
                self._loading_widget = LoadingIndicator(id="loading")
                self.left_panel.mount(self._loading_widget)
                left_widget.update("")
            return

        with open(stats_file, "r", encoding="utf-8") as f:
            content = f.read()
        left_widget.update(content)

        # remove loader if present
        if hasattr(self, "_loading_widget") and self._loading_widget:
            self._loading_widget.remove()
            self._loading_widget = None

        # --- RIGHT PANEL: flows JSON file ---
        table = self.right_panel.query_one("#json_table", DataTable)
        table.styles.max_height = 30
        table.header_height = 2

        json_file = getattr(self, "current_flow_file", "tmp/filtered_flows.json")
        if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    flows = json.load(f)
            except json.JSONDecodeError:
                flows = []
        else:
            flows = []

        # skip update if unchanged
        if getattr(self, "_last_flows", None) == flows:
            return  
        
        self._last_flows = flows
        table.clear()
        if not table.columns:
            for col in constant.COLUMNS:
                table.add_column(f"\n{col}")

        if flows:
            for flow in flows:
                row = [flow.get(key, "N/A") for key in constant.COLUMNS_FROM_FILE]
                sni = flow.get("sni") or flow.get("url", "N/A")
                row[3] = sni  
                table.add_row(*row)
        else:
            table.add_row(*constant.EMPTY_ROW)

    def on_select_changed(self, event: Select.Changed) -> None:

        # handle dropdown change (statistics or flows)
        key = event.value
        select_id = event.select.id

        # ignore blank selections
        if key == Select.BLANK:
            return

        if select_id == "statistics_select":
            # get the path of the selected file for the left panel
            _, file_path = constant.GROUPS["statistics"][key]
            self.current_stats_file = file_path
            self.update_left_panel(file_path)

        elif select_id == "flows_select":
            # get the path of the selected file for the right panel
            _, file_path = constant.GROUPS["flows"][key]
            self.current_flow_file = file_path  # update the current file
            self.update_right_panel(file_path)

    def update_left_panel(self, file_path):
        
        left_widget = self.left_panel.query_one("#left_text", Static)
        left_widget.styles.text_wrap = "wrap"
        left_widget.styles.text_overflow = "fold"
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            left_widget.update(content)

    def update_right_panel(self, file_path):

        # same of refresh
        table = self.right_panel.query_one("#json_table", DataTable)
        table.styles.max_height = 30
        table.header_height = 2
        table.clear()
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    flows = json.load(f)
            except json.JSONDecodeError:
                flows = []
        else:
            flows = []

        if not table.columns:
            for col in constant.COLUMNS:
                table.add_column(col)

        if flows:
            for flow in flows:
                row = [flow.get(key, "N/A") for key in constant.COLUMNS_FROM_FILE]
                sni = flow.get("sni") or flow.get("url", "N/A")
                row[3] = sni
                table.add_row(*row)
        else:
            table.add_row(*constant.EMPTY_ROW)

if __name__ == "__main__":
    PipelineInputs().run()
