import json

def calculate_coverage(flows_file, total_sni_file, recognized_file):
    # Carica i dati dai file
    with open(flows_file, "r") as f:
        final_flows = json.load(f)
    with open(total_sni_file, "r") as f:
        total_sni = set(json.load(f)["sni"])
    with open(recognized_file, "r") as f:
        recognized_rules = json.load(f)

    # Estrai gli SNI riconosciuti dalle regole
    recognized_sni = set()
    for rule in recognized_rules:
        recognized_sni.update(rule.get("sni_list", []))

    false_positives = recognized_sni.difference(total_sni)
    recognized_sni = recognized_sni.intersection(total_sni)

    print(f"Total SNI: {false_positives}")

    def matches_any(flow_sni, sni_set):
        if not flow_sni:
            return False
        return any(flow_sni.endswith(s) for s in sni_set)
    
    def count_packets(flow):
        total = 0
        for exch in flow.get("exchanged_packets", []):
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    total += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue
        return total

   # Calcolo pacchetti totali
    total_packets = 0
    for flow in final_flows:
        sni = flow.get("sni", "")
        #if matches_any(sni, total_sni):
        total_packets += count_packets(flow)

    # Calcolo pacchetti riconosciuti
    recognized_packets = 0
    for flow in final_flows:
        sni = flow.get("sni", "")
        if matches_any(sni, recognized_sni):
            recognized_packets += count_packets(flow)

    coverage = (recognized_packets / total_packets * 100) if total_packets > 0 else 0.0

    return {
        "total_packets": total_packets,
        "recognized_packets": recognized_packets,
        "coverage_percent": round(coverage, 2),
        "false_positives": false_positives  # elenco SNI che erano in recognized ma non in total
    }