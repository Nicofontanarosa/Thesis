
#################################################################
# File: functions.py
#################################################################

from collections import Counter
import json
import re
import os
from collections import defaultdict
# my file
import config
import constants
import get_info
import rank_sni
import group_sni

# protocols to keep
protocols = constants.PROTOCOLS

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

def print_risky_flows(final_flows, log_risky_flows="tmp/log_risky_flows.txt"):

    config.clear_log(log_risky_flows)

    for flow in final_flows:
        # check if the flow has any key containing "risk"
        risk_keys = [k for k in flow.keys() if "risk" in k.lower()]
        if not risk_keys:
            continue  # skip flows without risk

        config.log_message("\n\n>> Risky Flow:\n\n", log_risky_flows)
        for k, v in flow.items():
            if k in risk_keys:
                config.log_message(f"  + [red]{k}: {v}[/red]\n", log_risky_flows)  # red for risk
            elif "sni" in k.lower() or "hostname" in k.lower():
                config.log_message(f"  + [green]{k}: {v}[/green]\n", log_risky_flows)  # green for SNI/hostname
            else:
                v = str(v).replace('[', '\\[').replace(']', '\\]')
                config.log_message(f"  + {k}: {v}\n", log_risky_flows)

# -------------------------------------------

def normalize_sni_clusters(clusters, sorted_dataset):
    
    def normalize_sni(sni):
        # Remove 'www.' prefix
        if sni.lower().startswith("www."):
            sni = sni[4:]

        parts = sni.split(".")
        # Split by '.' and remove parts with numbers until we find a "clean" part
        keep = []
        for part in reversed(parts):
            if any(c.isdigit() for c in part):
                break  # stop qui → scarto tutto ciò che sta a sinistra
            keep.append(part)

         # keep ora è al contrario → ricostruisco nel giusto ordine
        keep = list(reversed(keep))
        normalized = ".".join(keep)

        # se rimane solo 1 pezzo → scarto del tutto
        if len(keep) <= 1:
            return None
        return normalized

    normalized_clusters = []
    for cluster in clusters:
        # Normalize each SNI ed elimina quelli None
        normalized_snis = [normalize_sni(sni) for sni in cluster["sni_list"]]
        normalized_snis = [sni for sni in normalized_snis if sni is not None]

        # Remove SNIs presenti in sorted_dataset
        filtered_snis = [sni for sni in normalized_snis if sni.lower() not in sorted_dataset]

        # Se il cluster ha ancora SNIs → lo tengo
        if filtered_snis:
            new_cluster = cluster.copy()
            new_cluster["sni_list"] = filtered_snis
            normalized_clusters.append(new_cluster)

    return normalized_clusters

def generate_rules(final_flows, output_file, dataset_file="dataset.json", datasetTLD_file="datasetTLD.json"):
    # Create the complete path for the intermediate JSON file
    output_folder = os.path.dirname(output_file)
    base, _ = os.path.splitext(os.path.basename(output_file))
    json_time_ndpi = os.path.join(output_folder, base + "_k.json")

    # Load the main dataset of known domains
    with open(dataset_file, "r") as f:
        dataset = json.load(f)
    dataset_domains = {d.lower() for d in dataset.get("domains", [])}
    # Sort dataset domains by length descending to match longer suffixes first
    sorted_dataset = sorted(dataset_domains, key=len, reverse=True)

    # Load the TLD dataset, assumed to be pre-sorted
    with open(datasetTLD_file, "r") as f:
        datasetTLD = json.load(f)
    datasetTLD_domains = {d.lower() for d in datasetTLD.get("domains", [])}

    # Collect all SNIs seen in the final flows
    sni_list = [flow.get("sni") for flow in final_flows if "sni" in flow and flow["sni"]]
    unique_sni = sorted(set(sni_list))

    # Print all SNIs detected in the flows
    print("\nAll SNIs seen:")
    for sni in unique_sni:
        print(f"  ├── \033[1;32m{sni}\033[0m")

    cleaned_snis = set()
    removed_TLD_parts = []

    # Remove flows with SNIs containing excluded words or present in the main dataset
    removed_flows = [
        flow for flow in final_flows
        if not flow.get("sni") 
        or any(word in flow.get("sni").lower() for word in constants.EXCLUDE_WORDS) 
        or flow.get("sni").lower() in sorted_dataset
    ]

    print("\nRemoved flows:")
    for flow in removed_flows:
        print(f"  ├── {flow.get('sni', '<no SNI>')}")

    # Keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if flow not in removed_flows
    ]

    for flow in final_flows:
        sni = flow.get("sni", "").lower()

        # Initialize a processed SNI variable
        sni_proc = sni

        # 1) Remove known suffixes from the main dataset (longest first)
        for d in sorted_dataset:
            if sni_proc.endswith("." + d):
                prefix = sni_proc[:-(len(d) + 1)]
                # If nothing left after removal, discard
                sni_proc = prefix if prefix else ""
                break
        if not sni_proc:
            continue

        print(f"\n[DEBUG] Original SNI: {sni} → After removing dataset suffix: {sni_proc}")

        # 2) Replace multiple consecutive hyphens with a single dot
        sni_proc = re.sub(r"-+", ".", sni_proc)
        parts = sni_proc.split(".")
        new_parts = []

        # 3) Remove unwanted parts: numeric, too short, or present in datasetTLD
        for p in parts:
            if len(p) <= constants.N_MIN or re.search(r"\d", p) or p in datasetTLD_domains:
                if p in datasetTLD_domains:
                    removed_TLD_parts.append(p)
                continue
            new_parts.append(p)
        parts = new_parts

        print(f"\n[DEBUG] After removing numeric/short/TLD parts: {parts}")

        if not parts:
            continue

        # Rejoin cleaned parts into the processed SNI
        sni_proc = ".".join(parts)
        # Add cleaned SNI to the set
        cleaned_snis.add(sni_proc)

    print(f"\nCleaned SNIs: {cleaned_snis}")

    # Prepare to collect clusters grouped by (ja3s, ja4) keys
    printed_snis = set()
    clusters = defaultdict(list)

    for flow in final_flows:
        sni_orig = flow.get("sni", "")
        if sni_orig:
            # Normalize the original SNI by replacing multiple hyphens with dots
            sni_norm = re.sub(r"-+", ".", sni_orig.lower())
            # Check if any cleaned SNI parts are contained in the normalized original SNI
            for sni_clean in cleaned_snis:
                parts = sni_clean.split(".")
                if all(part in sni_norm for part in parts):
                    # Add original SNI to printed set
                    printed_snis.add(sni_orig)

                    ja3s = flow.get("ja3s")
                    ja4 = flow.get("ja4")
                    if ja4:
                        # Keep only the last 2 parts of ja4
                        parts = ja4.split("_")
                        if len(parts) >= 2:
                            ja4 = "_".join(parts[-2:])
                    key = (ja3s, ja4)
                    clusters[key].append(flow)
                    break

    # Print all unique SNIs remaining after cleaning
    print("\nSNIs remaining (without duplicates):")
    for sni in sorted(printed_snis):
        print(f"  ├── \033[1;32m{sni}\033[0m")

    risultato = []

    for (ja3s, ja4), elements in clusters.items():

        # Collect all unique SNI values
        sni_list = sorted({e.get("sni") for e in elements if e.get("sni")})

        # Case 1: TLS flows → use JA3S + JA4 + SNI
        if ja3s or ja4:
            risultato.append({
                "ja3s": ja3s,
                "ja4": ja4,
                "sni_list": sni_list,
            })

        # Case 2: Non-TLS → cluster only by SNI
        else:
            for sni in sni_list:
                risultato.append({
                    "ja3s": None,
                    "ja4": None,
                    "sni_list": [sni],
                })

    #print(f"\nClusters before merging:\n{risultato}\n")

    # Merge clusters with the existing merging function
    sni_to_use = group_sni.merge_clusters(risultato)
    sni_to_use = normalize_sni_clusters(sni_to_use, sorted_dataset)

    #print(f"\nFinal clusters to classify {sni_to_use}\n")

    if constants.CLUSTER_RANKING:
        # Rank SNIs in final_flows and output ranking to json_time_ndpi
        rank_sni.rank_sni(final_flows, json_time_ndpi, sni_to_use)

    #print(f"\nClusters after merging:\n{sni_to_use}\n")

    # Save the final merged data to a JSON file
    with open("test.json", "w", encoding="utf-8") as f:
        json.dump(sni_to_use, f, indent=4)

    # Call classification on the cleaned and merged SNIs outputting to the specified file
    get_info.classify_domains(sni_to_use, output_file)

#################################################################
# End of functions.py
#################################################################