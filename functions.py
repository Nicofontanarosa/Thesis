
#################################################################
# File: functions.py
#################################################################

from collections import Counter
import json
import re
from collections import defaultdict
# my file
import config
import constants
import get_info
import group_sni

# protocols to keep
protocols = constants.PROTOCOLS

# -------------------------------------------

def normalize_sni_clusters(clusters, sorted_dataset):
    
    def normalize_sni(sni):
        # remove 'www.' prefix
        if sni.lower().startswith("www."):
            sni = sni[4:]

        # split the domain into components (e.g., ["api", "google", "com"])
        parts = sni.split(".")
        # split by '.' and remove parts with numbers until we find a "clean" part
        keep = []
        for part in reversed(parts):
            if any(c.isdigit() for c in part):
                break
            keep.append(part)

        # keep it's now at reverse order
        keep = list(reversed(keep))
        normalized = ".".join(keep)

        if len(keep) <= 1:
            return None
        return normalized

    normalized_clusters = []
    for cluster in clusters:
        # normalize each SNI ed elimina quelli None
        normalized_snis = [normalize_sni(sni) for sni in cluster["sni_list"]]
        normalized_snis = [sni for sni in normalized_snis if sni is not None]

        # remove SNIs presenti in sorted_dataset
        filtered_snis = [sni for sni in normalized_snis if sni.lower() not in sorted_dataset]

        # keep the cluster only if it still has valid SNIs
        if filtered_snis:
            new_cluster = cluster.copy()
            new_cluster["sni_list"] = filtered_snis
            normalized_clusters.append(new_cluster)

    return normalized_clusters

def normalize_ja4(ja4: str) -> str:
    if not ja4:
        return ja4
    parts = ja4.split("_")
    if len(parts) >= 2:
        return "_".join(parts[-2:])
    return ja4

# -------------------------------------------

def filter_top_clusters(clusters, total_packets):

    # keep only clusters that contribute at least TOP_PERCENT of packets
    pkt_threshold = total_packets * constants.TOP_PERCENT

    print(f"\n[DEBUG] Threshold: {pkt_threshold}")

    filtered_clusters = [
        cluster for cluster in clusters
        if cluster.get("packets", 0) >= pkt_threshold
    ]

    return filtered_clusters

# -------------------------------------------

def aggregate_flows_by_sni(raw_clusters, final_flows):
    
    # initialize counters for each cluster
    for cluster in raw_clusters:
        cluster["flow_count"] = 0
        cluster["packets"] = 0

    # aggregate flows into correct clusters
    for flow in final_flows:

        flow_ja4 = normalize_ja4((flow.get("ja4")))
        flow_ja3s = (flow.get("ja3s"))
        flow_cert = {
            "certificate": flow.get("certificate"),
            "subject": flow.get("subject"),
            "issuer": flow.get("issuer"),
            "servernames": flow.get("servernames")
        }
        flow_sni = (flow.get("sni") or "").lower()
        similar_count = flow.get("similar_flows_count", 0)
        exchanged = flow.get("exchanged_packets", [])

        # count total packets exchanged
        pkt = 0
        for exch in exchanged:
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    pkt += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue

        # try to match this flow with a cluster
        for cluster in raw_clusters:

            # extract fields from cluster for comparison
            cluster_sni_list = [s.lower() for s in cluster.get("sni_list", []) if s]
            ja4_match = flow_ja4 == cluster.get("ja4")
            ja3s_match = flow_ja3s == cluster.get("ja3s")
            cluster_cert_dict = {k: v for k, v in cluster.get("certificate", [])}
            cert_match = all(
                flow_cert.get(k) == cluster_cert_dict.get(k)
                for k in ["certificate", "issuer", "servernames", "subject"]
                if cluster_cert_dict.get(k) is not None
            )

            # --- Priority 1: match by SNI ---
            if cluster_sni_list and any(flow_sni == s or flow_sni.endswith("." + s) for s in cluster_sni_list):
                cluster["flow_count"] += similar_count
                cluster["packets"] += pkt
                break

            # --- Priority 2: no SNI available, match by ja3s, ja4, and cert ---
            elif not cluster_sni_list and ja4_match and ja3s_match and cert_match:
                cluster["flow_count"] += similar_count
                cluster["packets"] += pkt
                break

    return raw_clusters

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

def generate_rules(final_flows, output_file, sni_stats_file="tmp/sni_stats.txt", log_file_removed_flows="tmp/removed_flows.json", log_file_filtered_flows="tmp/filtered_flows.json", dataset_file="dataset/dataset.json", datasetTLD_file="dataset/datasetTLD.json", dataset_not_protocols_file="dataset/dataset_not_protocols_domains.json"):

    # load the main dataset of known domains
    with open(dataset_file, "r") as f:
        dataset = json.load(f)
    dataset_domains = {d.lower() for d in dataset.get("domains", [])}
    # sort dataset domains by length descending to match longer suffixes first
    sorted_dataset = sorted(dataset_domains, key=len, reverse=True)

    # load the TLD dataset
    with open(datasetTLD_file, "r") as f:
        datasetTLD = json.load(f)
    datasetTLD_domains = {d.lower() for d in datasetTLD.get("domains", [])}

    # load the dataset of known non-protocol domains
    with open(dataset_not_protocols_file, "r") as f:
        dataset_not_protocols = json.load(f)
    dataset_not_protocols_domains = {d.lower() for d in dataset_not_protocols.get("domains", [])}

    # --------------------------------

    # collect all SNIs seen in the final flows
    sni_list = [flow.get("sni") for flow in final_flows if "sni" in flow and flow["sni"]]
    unique_sni = sorted(set(sni_list))

    # print all SNIs detected in the flows
    config.log_message("\n\n>> All SNIs seen:\n\n", sni_stats_file)
    for sni in unique_sni:
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # --------------------------------

    # count the total number of packets in final_flows
    total_packets = 0

    for flow in final_flows:

        exchanged = flow.get("exchanged_packets", [])
        for exch in exchanged:
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    total_packets += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue

    print(f"\n[DEBUG] Total packets: {total_packets}")

    # --------------------------------

    # SNIs filtered for debugging
    cleaned_snis = set()
    # clusters grouped by (ja3s, ja4, certificate) keys
    clusters = defaultdict(list)
    # raw clusters before normalization
    raw_clusters = []

    print(f"\n[DEBUG] Starting with:\n\n{final_flows}\n")

    # remove flows with SNIs containing excluded words or present in the main dataset
    removed_flows = [
        flow for flow in final_flows
            if (flow.get("sni") and any(word in flow.get("sni").lower() for word in constants.EXCLUDE_WORDS))
            or (flow.get("sni") and flow.get("sni").lower() in sorted_dataset)
    ]

    config.log_message("\n\n>> Removed flows 1° filtering ( Exclude words and know domains ):\n\n", sni_stats_file)
    for flow in removed_flows:
        config.log_message(f"   [+] [red]{flow.get('sni', '')}[/red]\n", sni_stats_file)

    # keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if flow not in removed_flows
    ]

    config.log_message(f"\n>> Removed flows after 1° SNI filtering [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows, log_file_removed_flows)

    # reset for next filtering step
    removed_flows = [] 
    # flows removed during JA3S/JA4 filtering
    removed_flows_ja = []

    # --------------------------------

    config.log_message("\n\n>> Removed flows 2° filtering ( Remove known suffixes and not_protocols domains ):\n\n", sni_stats_file)

    for flow in final_flows:
        
        sni = flow.get("sni")
        if sni:

            # initialize a processed SNI variable
            sni = sni.lower()
            sni_proc = sni

            print(f"\n[DEBUG] Processing: {sni}")

            if constants.SHOW_NDPI_PROTOCOLS:

                # 1) remove known suffixes from the main dataset (longest first)
                for d in sorted_dataset:
                    if sni_proc.endswith("." + d):
                        prefix = sni_proc[:-(len(d) + 1)]
                        # if nothing left after removal, discard
                        sni_proc = prefix if prefix else ""
                        break
                if not sni_proc:
                    config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                    removed_flows.append(flow)
                    continue

            else:

                # 1) remove snis present in the main dataset
                remove_sni = False
                for d in sorted_dataset:
                    if sni_proc.endswith(d):
                        remove_sni = True
                        break
                if remove_sni:
                    config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                    removed_flows.append(flow)
                    continue

            print(f"\n[DEBUG] Original SNI: {sni} → After removing dataset suffix: {sni_proc}")

            # remove not_protocols domains
            remove_sni = False
            for d in dataset_not_protocols_domains:
                if sni_proc.endswith(d):
                    remove_sni = True
                    break
            if remove_sni:
                config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                removed_flows.append(flow)
                continue

            # 2) replace multiple consecutive hyphens with a single dot
            sni_proc = re.sub(r"-+", ".", sni_proc)
            parts = sni_proc.split(".")
            new_parts = []

            # 3) remove unwanted parts: numeric, too short, or present in datasetTLD
            for p in parts:
                if len(p) <= constants.N_MIN or re.search(r"\d", p) or p in datasetTLD_domains:
                    continue
                else:
                    new_parts.append(p)
            parts = new_parts

            print(f"\n[DEBUG] After removing numeric/short/TLD parts: {parts}")

            if not parts:
                config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                removed_flows.append(flow)
                continue

            # add remaining SNI to the set
            cleaned_snis.add(sni)

        ja3s = flow.get("ja3s")
        ja4 = flow.get("ja4")
        certificate = {
            "certificate": flow.get("certificate"),
            "subject": flow.get("subject"),
            "issuer": flow.get("issuer"),
            "servernames": flow.get("servernames")
        }

        print(f"\n[DEBUG] Flow → JA3S: {ja3s}, JA4: {ja4}, Cert: {certificate}")

        if not (ja3s or ja4 or certificate["certificate"] or certificate["subject"] or certificate["issuer"] or certificate["servernames"] or sni):
            removed_flows_ja.append(flow)
            print(f"\n[DEBUG] Removed flow due to missing JA3S/JA4/Cert/SNI: {flow}")
            continue

        ja4 = normalize_ja4(ja4)

        # create a hashable key for the certificate dictionary
        cert_tuple = tuple(sorted(certificate.items()))
        key = (ja3s, ja4, cert_tuple)

        clusters[key].append(flow)
    
    config.log_message(f"\n>> Removed flows after SNI filtering ( Remove known suffixes and not_protocols domains ) [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows, log_file_removed_flows)
    config.log_message(f"\n>> Removed flows after JA3S/JA4/Certificate filtering [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows_ja, log_file_removed_flows)

    config.log_message(f"\n\n>> Remaining SNIs:\n\n", sni_stats_file)
    for sni in sorted(cleaned_snis):
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # --------------------------------

    for (ja3s, ja4, certificate), elements in clusters.items():

        # collect all unique SNI values
        sni_list = sorted({e.get("sni") for e in elements if e.get("sni")})

        raw_clusters.append({
            "ja3s": ja3s,
            "ja4": ja4,
            "certificate": certificate,
            "sni_list": sni_list,
        })

    print(f"\n[DEBUG] Raw Cluster: {raw_clusters}")

    # count flows using raw cluster information
    raw_clusters = aggregate_flows_by_sni(raw_clusters , final_flows)

    # save the raw clusters
    with open("tmp/raw_clusters.json", "w", encoding="utf-8") as f:
        json.dump(raw_clusters, f, indent=4)

    # merge clusters based on SNI
    sni_to_use = group_sni.merge_clusters(raw_clusters)

    print(f"\n[DEBUG] Merged Cluster: {sni_to_use}")

    if not constants.SHOW_NDPI_PROTOCOLS:
        sni_to_use = normalize_sni_clusters(sni_to_use, sorted_dataset)

    # keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if (flow not in removed_flows) and (flow not in removed_flows_ja)
    ]

    config.clear_log(log_file_filtered_flows)
    config.log_message(final_flows, log_file_filtered_flows)

    # keep only the clusters above the threshold (IMPORTANT)
    top_clusters = filter_top_clusters(sni_to_use, total_packets)

    # save the final merged data to a JSON file
    with open("tmp/clusters.json", "w", encoding="utf-8") as f:
        json.dump(top_clusters, f, indent=4)

    # call classification on the cleaned and merged SNIs outputting to the specified file
    get_info.classify_domains(top_clusters, output_file)

    return final_flows

#################################################################
# End of functions.py
#################################################################