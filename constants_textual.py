

# Example groups definition
GROUPS = {
    "flows": {
        "filtered": ("Filtered-Flows", "tmp/filtered_flows.json"),
        "incomplete": ("Incomplete-Flows", "tmp/incomplete_flows.json"),
        "general": ("General-Flows", "tmp/general_flows.json"),
        "ipvsix": ("IPv6-Flows", "tmp/ipvsix_flows.json"),
        "nosni": ("No-SNI-Flows", "tmp/nosni_flows.json"),
        "maxsni": ("Max-SNI-Length-Flows", "tmp/removed_flows_maxsni.json"),
        "empty": ("Empty-Flows", "tmp/empty_flows.json")
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

# Key bindings
BINDINGS = [("q", "quit", "Quit")]
TITLE = "My Custom Flow Viewer"
SUB_TITLE = "Analyse and Debug Network Flows"
