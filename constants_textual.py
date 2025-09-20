

# Example groups definition
GROUPS = {
    "flows": {
        "filtered": ("Filtered-Flows", "tmp/filtered_flows.json")
    },
    "statistics": {
        "path": ("Path-file", "tmp/initialization.txt"),
        "flowsnumber": ("Flows-Number","tmp/flows.txt"),
        "stats": ("Stats", "tmp/stats.txt"),
        "rule": ("Custom-Rules-nDPI", "tmp/rules.txt"),
        "timeSNI": ("Time rank SNI", "tmp/rank_time_sni.txt"),
        "rankSNI": ("Occurence rank SNI", "tmp/rank_sni.txt"),
        "riskyflows": ("Risky Flows", "tmp/log_risky_flows.txt")
    }
}

# Default table columns
COLUMNS = ["Protocol", "Source IP", "Destination IP", "SNI/URL", "Similar Flows", "Risk"]
COLUMNS_FROM_FILE = ["proto_field", "ip_source", "ip_destination", "sni", "similar_flows_count", "risk"]
# Default values for empty rows
EMPTY_ROW = ["N/A", "N/A", "N/A", "N/A", "No data", "None"]

# Key bindings
BINDINGS = [("q", "quit", "Quit")]
TITLE = "My Custom Flow Viewer"
SUB_TITLE = "Analyse and Debug Network Flows"
