

# Example groups definition
GROUPS = {
    "flows": {
        "filtered": ("Filtered-Flows", "tmp/filtered_flows.json"),
        "maxsni": ("Max-SNI-Length-Flows", "tmp/removed_flows_maxsni.json")
    },
    "statistics": {
        "path": ("Path-file", "tmp/initialization.txt"),
        "flowsnumber": ("Flows-Number","tmp/flows.txt"),
        "stats": ("Stats", "tmp/stats.txt"),
        "rule": ("Custom-Rules-nDPI", "tmp/rules.txt")
    }
}

# Default table columns
COLUMNS = ["Protocol", "Source IP", "Destination IP", "SNI/URL", "Risk"]
COLUMNS_FROM_FILE = ["proto_field", "ip_source", "ip_destination", "sni", "risk"]
# Default values for empty rows
EMPTY_ROW = ["N/A", "N/A", "N/A", "No data", "None"]

# Key bindings
BINDINGS = [("q", "quit", "Quit")]
TITLE = "My Custom Flow Viewer"
SUB_TITLE = "Analyse and Debug Network Flows"
