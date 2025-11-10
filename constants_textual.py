
# groups definition to visualize
GROUPS = {
    "flows": {
        "filtered": ("Filtered-Flows", "tmp/filtered_flows.json"),
        "finalflows": ("Final-Flows", "tmp/final_output.json"),
        "allflows": ("All-Flows", "tmp/final_complete_output.json")
    },
    "statistics": {
        "path": ("Path-file", "tmp/initialization.txt"),
        "flowsnumber": ("Flows-Number","tmp/flows.txt"),
        "stats": ("Stats", "tmp/stats.txt"),
        "rule": ("Custom-Rules-nDPI", "tmp/rules.txt"),
        "statsSNI": ("SNI Stats", "tmp/sni_stats.txt"),
        "riskyflows": ("Risky Flows", "tmp/log_risky_flows.txt"),
        "coverage": ("Coverage of Rules", "tmp/coverage.txt"),
        "parameters": ("Parameters Used", "tmp/parameters.txt")
    }
}

# default table columns
COLUMNS = ["Protocol", "Source IP", "Destination IP", "SNI/URL", "JA3S", "JA4", "Similar Flows", "Risk"]
COLUMNS_FROM_FILE = ["proto_field", "ip_source", "ip_destination", "sni", "ja3s", "ja4", "similar_flows_count", "risk"]
# default values for empty rows
EMPTY_ROW = ["N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "No data", "None"]

# key bindings and constants
BINDINGS = [("q", "quit", "Quit")]
TITLE = "My Custom Flow Viewer"
SUB_TITLE = "Analyse and Debug Network Flows"
