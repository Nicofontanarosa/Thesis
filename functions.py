
#################################################################
# File: functions.py
#################################################################

from collections import Counter
import json
import re
# my file
import config
import get_info

# protocols to keep
protocols = config.PROTOCOLS

# -------------------------------------------

def protocols_summary(flows):

    protocol_cou = Counter()

    for flow in flows:
        proto = flow.get("proto_field", "").lower()

        # search for known protocols
        matched = False
        for p in protocols:
            if p.lower() in proto:
                protocol_cou[p] += 1
                matched = True
                break

        # if no known protocol matched, count as Unknown
        if not matched:
            protocol_cou["Unknown"] += 1

    return protocol_cou

# -------------------------------------------

def print_risky_flows(final_flows):

    for flow in final_flows:
        # check if the flow has any key containing "risk"
        risk_keys = [k for k in flow.keys() if "risk" in k.lower()]
        if not risk_keys:
            continue  # skip flows without risk

        print("--- Risky Flow ---")
        for k, v in flow.items():
            if k in risk_keys:
                print(f"  ├── \033[1;31m{k}: {v}\033[0m")  # red for risk
            elif "sni" in k.lower() or "hostname" in k.lower():
                print(f"  ├── \033[1;32m{k}: {v}\033[0m")  # green for SNI/hostname
            else:
                print(f"  ├── {k}: {v}")
        print("\n")

# -------------------------------------------

def print_flow(prot, final_flows):

    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if prot in proto:
            for k, v in flow.items():
                if "risk" in k.lower():
                    print(f"  ├── \033[1;31m{k}: {v}\033[0m")
                elif "sni" in k.lower() or "hostname" in k.lower():
                    print(f"  ├── \033[1;32m{k}: {v}\033[0m")
                else:
                    print(f"  ├── {k}: {v}")
            print("\n")

def print_flows(final_flows):

    protocol_counts = protocols_summary(final_flows)

    # printing summary
    summary = ", ".join([f"{v} flows {k}" for k, v in protocol_counts.items()])
    print(f"\nDetected: {summary}\n")

    # printing flows with risk
    print_risky_flows(final_flows)

    # --- DNS FLOWS PRINT ---
    print("DNS flows detected:\n")
    print_flow("dns", final_flows)

    # --- HTTP FLOWS PRINT ---
    print("\nHTTP flows detected:\n")
    print_flow("http", final_flows)

    # --- TLS FLOWS PRINT ---
    print("\nTLS flows detected:\n")
    print_flow("tls", final_flows)

    # --- QUIC FLOWS PRINT ---
    print("\nQUIC flows detected:\n")
    print_flow("quic", final_flows)

    # --- SMTP FLOWS PRINT ---
    print("\nSMTP flows detected:\n")
    print_flow("smtp", final_flows)

    # --- UNKNOWN FLOWS PRINT ---
    print("\nUnknown flows detected:\n")
    print_flow("unknown", final_flows)

# -------------------------------------------

def generate_rules(final_flows, output_file, dataset_file="dataset.json", datasetTLD_file="datasetTLD.json"):

    # load the main dataset of known domains
    with open(dataset_file, "r") as f:
        dataset = json.load(f)
    dataset_domains = {d.lower() for d in dataset.get("domains", [])}
    # sort the dataset by length in descending order to match longer suffixes first
    sorted_dataset = sorted(dataset_domains, key=len, reverse=True)

    # load the TLD dataset already ordered
    with open(datasetTLD_file, "r") as f:
        datasetTLD = json.load(f)
    datasetTLD_domains = {d.lower() for d in datasetTLD.get("domains", [])}

    # collect all SNIs seen
    sni_list = [flow.get("sni") for flow in final_flows if "sni" in flow and flow["sni"]]
    unique_sni = sorted(set(sni_list))

    # print all SNIs detected in the flows
    print("\nAll SNIs seen:")
    for sni in unique_sni:
        print(f"  ├── \033[1;32m{sni}\033[0m")

    cleaned_snis = set()

    # remove flows with SNIs containing excluded words or present in the main dataset
    removed_flows = [
        flow for flow in final_flows
        if not flow.get("sni") 
        or any(word in flow.get("sni").lower() for word in config.EXCLUDE_WORDS) 
        or flow.get("sni").lower() in sorted_dataset
    ]

    print("\nRemoved flows:")
    for flow in removed_flows:
        print(f"  ├── {flow.get('sni', '<no SNI>')}")

    final_flows = [
        flow for flow in final_flows
        if flow not in removed_flows
    ]

    for flow in final_flows:
        sni = flow.get("sni", "").lower()

        # initialize sni_proc
        sni_proc = sni

        # 1) Truncate known suffixes from the main dataset ( longest first )
        for d in sorted_dataset:
            if sni_proc.endswith("." + d):
                prefix = sni_proc[: -(len(d) + 1)]
                # if nothing left, discard
                sni_proc = prefix if prefix else ""
                break
        if not sni_proc:
            continue

        print(f"[DEBUG] After main dataset cut: {sni} -> {sni_proc}")

        # 2) Replace multiple consecutive hyphens with a single dot
        sni_proc = re.sub(r"-+", ".", sni_proc)
        # split the remaining SNI into parts
        parts = sni_proc.split(".")
        # 3) Remove unwanted parts: numbers, too short, or present in datasetTLD
        parts = [p for p in parts if len(p) > config.N_MIN and not re.search(r"\d", p) and p not in datasetTLD_domains]

        if not parts:
            continue

        # rejoin the cleaned parts
        sni_proc = ".".join(parts)
        # add the cleaned SNI to the set
        cleaned_snis.add(sni_proc)

        print(f"[DEBUG] After second dataset cut: {sni_proc}")

    print(f"\nCleaned SNIs: {cleaned_snis}")

    # print SNIs mapped back to original flows
    print("\nSNIs remaining after clean_flows:")
    # use a set to avoid duplicates
    printed_snis = set()  

    for flow in final_flows:
        sni_orig = flow.get("sni", "")
        if not sni_orig:
            continue
        # normalize original SNI
        sni_norm = re.sub(r"-+", ".", sni_orig.lower())
        # check if any cleaned SNI is contained in the normalized original
        for sni_clean in cleaned_snis:
            parts = sni_clean.split(".")
            # check if all parts are present in the normalized original SNI
            if all(part in sni_norm for part in parts):
                # store original SNI
                printed_snis.add(sni_orig)
                break

    # print all unique SNIs after cleaning
    print("\nSNIs remaining (without duplicates):")
    for sni in sorted(printed_snis):
        print(f"  ├── \033[1;32m{sni}\033[0m")

    get_info.classify_domains(printed_snis, output_file)

#################################################################
# End of functions.py
#################################################################