
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

def aggregate_flows_by_sni(sni_to_use, final_flows, output_file="tmp/aggregated_flows.json"):

    aggregated = []

    # Step 1: aggregate flows for each SNI in the clusters
    for cluster in sni_to_use:
        sni_list = cluster.get("sni_list", [])
        # initialize counters for each SNI
        sni_counters = {sni: {"flow_count": 0, "packets": 0} for sni in sni_list}

        for flow in final_flows:
            flow_sni = (flow.get("sni") or "").lower()
            similar_count = flow.get("similar_flows_count", 0)
            exchanged = flow.get("exchanged_packets", [])

            # calculate total packets (sum of both directions)
            pkt = 0
            for exch in exchanged:
                if "<->" in exch:
                    left, right = exch.split("<->")
                    try:
                        pkt += int(left.strip()) + int(right.strip())
                    except ValueError:
                        continue

            # update counters if SNI matches
            for sni in sni_list:
                if flow_sni == sni or flow_sni.endswith("." + sni):
                    sni_counters[sni]["flow_count"] += 1 + similar_count
                    sni_counters[sni]["packets"] += pkt

        # append aggregated data
        for sni in sni_list:
            counters = sni_counters[sni]
            aggregated.append({
                "sni": sni,
                "flow_count": counters["flow_count"],
                "packets": counters["packets"]
            })

    # save aggregated data for reference
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=4, ensure_ascii=False)

    # Step 2: calculate the cumulative packet threshold for top SNI
    total_pkts = sum(entry["packets"] for entry in aggregated)
    threshold = total_pkts * constants.TOP_PERCENT

    # Step 3: determine top SNI based on packets
    
    top_sni = set()
    for entry in aggregated:
        if entry["packets"] >= threshold:
            top_sni.add(entry["sni"])

    # Step 4: filter original sni_to_use clusters keeping only top SNI
    filtered_clusters = []
    for cluster in sni_to_use:
        sni_list = [sni for sni in cluster.get("sni_list", []) if sni in top_sni]
        if sni_list:  # keep cluster only if it still has SNI
            filtered_clusters.append({
                "ja3s": cluster.get("ja3s"),
                "ja4": cluster.get("ja4"),
                "sni_list": sni_list
            })

    return filtered_clusters

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

def generate_rules(final_flows, output_file, sni_stats_file="tmp/sni_stats.txt", log_file_removed_flows="tmp/removed_flows.json", log_file_filtered_flows="tmp/filtered_flows.json", dataset_file="dataset/dataset.json", datasetTLD_file="dataset/datasetTLD.json", dataset_not_protocols_file="dataset/dataset_not_protocols_domains.json"):

    if constants.CLUSTER_RANKING:
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

    # Load the dataset of known non-protocol domains
    with open(dataset_not_protocols_file, "r") as f:
        dataset_not_protocols = json.load(f)
    dataset_not_protocols_domains = {d.lower() for d in dataset_not_protocols.get("domains", [])}

    # --------------------------------

    # Collect all SNIs seen in the final flows
    sni_list = [flow.get("sni") for flow in final_flows if "sni" in flow and flow["sni"]]
    unique_sni = sorted(set(sni_list))

    # Print all SNIs detected in the flows
    config.log_message("\n\n>> All SNIs seen:\n\n", sni_stats_file)
    for sni in unique_sni:
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # --------------------------------

    cleaned_snis = set()
    removed_TLD_parts = []
    # clusters grouped by (ja3s, ja4) keys
    clusters = defaultdict(list)
    raw_clusters = []

    # Remove flows with SNIs containing excluded words or present in the main dataset
    removed_flows = [
        flow for flow in final_flows
            if any(word in flow.get("sni").lower() for word in constants.EXCLUDE_WORDS) 
            or flow.get("sni").lower() in sorted_dataset
    ]

    config.log_message("\n\n>> Removed flows 1° filtering ( Exclude words and know domains ):\n\n", sni_stats_file)
    for flow in removed_flows:
        config.log_message(f"   [+] [red]{flow.get('sni', '')}[/red]\n", sni_stats_file)

    # Keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if flow not in removed_flows
    ]

    # reset for next filtering step
    removed_flows = [] 

    # --------------------------------

    config.log_message("\n\n>> Removed flows 2° filtering ( Remove known suffixes and not_protocols domains ):\n\n", sni_stats_file)

    for flow in final_flows:
        sni = flow.get("sni", "").lower()

        # Initialize a processed SNI variable
        sni_proc = sni

        if constants.SHOW_NDPI_PROTOCOLS:

            # 1) Remove known suffixes from the main dataset (longest first)
            for d in sorted_dataset:
                if sni_proc.endswith("." + d):
                    prefix = sni_proc[:-(len(d) + 1)]
                    # If nothing left after removal, discard
                    sni_proc = prefix if prefix else ""
                    break
            if not sni_proc:
                removed_flows.append(flow)
                continue

        else:

            # 1) Remove snis present in the dataset
            remove_sni = False
            for d in sorted_dataset:
                if sni_proc.endswith(d):
                    remove_sni = True
                    break
            if remove_sni:
                config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                removed_flows.append(flow)
                continue

        # remove not_protocols domains
        #remove_sni = False
        #for d in dataset_not_protocols_domains:
        #    if sni_proc.endswith(d):
        #        remove_sni = True
        #        break
        #if remove_sni:
        #    config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
        #    removed_flows.append(flow)
        #    continue

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
            config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
            removed_flows.append(flow)
            continue

        # Add remaining SNI to the set
        cleaned_snis.add(sni)

        ja3s = flow.get("ja3s")
        ja4 = flow.get("ja4")

        if ja4:
            # Keep only the last 2 parts of ja4
            parts = ja4.split("_")
            if len(parts) >= 2:
                ja4 = "_".join(parts[-2:])
        
        key = (ja3s, ja4)
        clusters[key].append(flow)

    config.log_message(f"\n\n>> Remaining SNIs:\n\n", sni_stats_file)
    for sni in sorted(cleaned_snis):
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # Keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if flow not in removed_flows
    ]

    config.clear_log(log_file_filtered_flows)
    config.log_message(final_flows, log_file_filtered_flows)
    config.log_message(f"\n>> Removed flows after filtering [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows, log_file_removed_flows)

    # --------------------------------

    for (ja3s, ja4), elements in clusters.items():

        # Collect all unique SNI values
        sni_list = sorted({e.get("sni") for e in elements if e.get("sni")})

        raw_clusters.append({
            "ja3s": ja3s,
            "ja4": ja4,
            "sni_list": sni_list,
        })

    #print(f"\nClusters before merging:\n{raw_clusters}\n")

    # Merge clusters with the existing merging function
    sni_to_use = group_sni.merge_clusters(raw_clusters)

    if not constants.SHOW_NDPI_PROTOCOLS:
        sni_to_use = normalize_sni_clusters(sni_to_use, sorted_dataset)

    #print(f"\nFinal clusters to classify {sni_to_use}\n")

    if constants.WEB_TRAFFIC:
        sni_to_use = aggregate_flows_by_sni(sni_to_use, final_flows)

    if constants.CLUSTER_RANKING:
        # Rank SNIs in final_flows and output ranking to json_time_ndpi
        rank_sni.rank_sni(final_flows, json_time_ndpi, sni_to_use)

    #print(f"\nClusters after merging:\n{sni_to_use}\n")

    # Save the final merged data to a JSON file
    with open("clusters.json", "w", encoding="utf-8") as f:
        json.dump(sni_to_use, f, indent=4)

    # Call classification on the cleaned and merged SNIs outputting to the specified file
    get_info.classify_domains(sni_to_use, output_file)

    return final_flows

#################################################################
# End of functions.py
#################################################################