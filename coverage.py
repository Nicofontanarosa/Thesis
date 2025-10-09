
#################################################################
# File: coverage.py to 
#################################################################

import json

# -------------------------------------------

def calculate_coverage(flows_file, recognized_file):

    # Load flow data and recognized SNI rules
    with open(flows_file, "r") as f:
        final_flows = json.load(f)
    with open(recognized_file, "r") as f:
        recognized_rules = json.load(f)

    # Extract all recognized SNI from recognized clusters
    recognized_sni = set()
    for rule in recognized_rules:
        recognized_sni.update(rule.get("sni_list", []))

    def matches_any(flow_sni, sni_set):
        """Return True if flow_sni ends with any recognized SNI in the set."""
        if not flow_sni:
            return False
        return any(flow_sni.endswith(sni) or flow_sni == sni for sni in sni_set)

    def count_packets(flow):
        """Sum all packets exchanged in both directions."""
        total = 0
        for exch in flow.get("exchanged_packets", []):
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    total += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue
        return total

    # --- Step 1: Compute total packets and total flows ---
    total_packets = 0
    total_flows = 0
    for flow in final_flows:
        total_packets += count_packets(flow)
        total_flows += flow.get("similar_flows_count", 0)

    # --- Step 2: Compute recognized packets and flows ---
    recognized_packets = 0
    recognized_flows = 0
    for flow in final_flows:
        sni = (flow.get("sni") or "").lower()
        if matches_any(sni, recognized_sni):
            recognized_packets += count_packets(flow)
            recognized_flows += flow.get("similar_flows_count", 0)

    # --- Step 3: Compute percentages ---
    packet_coverage = (recognized_packets / total_packets * 100) if total_packets > 0 else 0.0
    flow_coverage = (recognized_flows / total_flows * 100) if total_flows > 0 else 0.0

    # --- Step 4: Return structured statistics ---
    return {
        "total_packets": total_packets,
        "recognized_packets": recognized_packets,
        "packet_coverage_percent": round(packet_coverage, 2),
        "total_flows": total_flows,
        "recognized_flows": recognized_flows,
        "flow_coverage_percent": round(flow_coverage, 2)
    }


#################################################################
# End of coverage.py
#################################################################