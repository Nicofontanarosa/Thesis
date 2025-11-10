
#################################################################
# File: coverage.py to 
#################################################################

import json
# my file
import functions

# ------------- Helper functions ------------

def matches_any_sni(flow_sni, sni_set):
    if not flow_sni: 
        return False 
    return any(flow_sni.endswith(sni) or flow_sni == sni for sni in sni_set)

def matches_any_cert(flow_cert, recognized_certs_list):
    for cert in recognized_certs_list:
        if all(v is None for v in cert.values()):
            continue
        if all(flow_cert.get(k) == cert.get(k) for k in cert.keys()):
            return True
    return False

def count_packets(flow):
    total = 0
    for exch in flow.get('exchanged_packets', []):
        if "<->" in exch:
            left, right = exch.split("<->")
            try:
                total += int(left.strip()) + int(right.strip())
            except ValueError:
                continue
    return total

# -------------------------------------------

def calculate_coverage(flows_file, recognized_file):

    # load flow data and recognized SNI rules
    with open(flows_file, "r") as f:
        final_flows = json.load(f)
    with open(recognized_file, "r") as f:
        recognized_rules = json.load(f)

    # extract all recognized SNI, JA4s, and certificates from groups
    recognized_sni = set()
    recognized_ja4 = set()
    recognized_certs = []
    for rule in recognized_rules:
        recognized_sni.update(rule.get('sni_list', []))
        recognized_ja4.add(rule.get('ja4'))
        # store certificates as dict for easy comparison
        cert_dict = {k: v for k, v in rule.get('certificate', []) if v is not None}
        recognized_certs.append(cert_dict)

    #print(f"\n[DEBUG] SNI rec: {recognized_sni}, JA4 rec: {recognized_ja4}, CERT rec: {recognized_certs}")

    # --- Step 1: Compute total packets and total flows ---
    total_packets = 0
    total_flows = 0
    for flow in final_flows:
        total_packets += count_packets(flow)
        total_flows += flow.get('similar_flows_count', 0)

    # --- Step 2: Compute recognized packets and flows ---
    recognized_packets = 0
    recognized_flows = 0

    for flow in final_flows:

        flow_sni = (flow.get('sni'))
        if flow_sni: flow_sni = flow_sni.lower()
        flow_ja4 = functions.normalize_ja4(flow.get('ja4'))
        flow_cert = {
            "certificate": flow.get('certificate'),
            "issuer": flow.get('issuer'),
            "servernames": flow.get('servernames'),
            "subject": flow.get('subject')
        }

        #print(f"\n[DEBUG] SNI flow: {flow_sni}, JA4 flow: {flow_ja4}, CERT flow: {flow_sni or flow_ja4 or flow_cert["certificate"] or flow_cert["issuer"] or flow_cert["servernames"] or flow_cert["subject"]}")

        recognized = False

        # --- Priority 1: SNI ---
        if flow_sni:
            if matches_any_sni(flow_sni, recognized_sni):
                recognized = True

        # --- Priority 2: Certificate ---
        elif any(flow_cert.values()):
            if matches_any_cert(flow_cert, recognized_certs):
                recognized = True

        # --- Priority 3: JA4 ---
        elif flow_ja4:
            if flow_ja4 in recognized_ja4:
                recognized = True

        # --- Count recognized flows ---
        if recognized:
            recognized_packets += count_packets(flow)
            recognized_flows += flow.get('similar_flows_count', 0)

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