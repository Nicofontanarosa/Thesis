
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
def find_ja4_by_suffix(ja4_suffix, flows):
    result = set()
    for flow in flows:
        ja4 = flow.get("ja4")
        if ja4 and ja4.endswith(ja4_suffix):
            result.add(ja4)
    return list(result)

# -------------------------------------------

def normalize_sni_groups(groups, sorted_dataset):
    
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

    normalized_groups = []
    for group in groups:
        # normalize each SNI ed delete None
        normalized_snis = [normalize_sni(sni) for sni in group["sni_list"]]
        normalized_snis = [sni for sni in normalized_snis if sni is not None]

        # remove SNIs in sorted_dataset
        filtered_snis = [sni for sni in normalized_snis if sni.lower() not in sorted_dataset]

        new_group = group.copy()
        new_group["sni_list"] = filtered_snis
        normalized_groups.append(new_group)

    return normalized_groups

def normalize_ja4(ja4: str) -> str:
    if not ja4:
        return ja4
    parts = ja4.split("_")
    if len(parts) >= 2:
        return "_".join(parts[-2:])
    return ja4

# -------------------------------------------

def filter_top_groups(final_flows, groups, total_packets):

    # keep only groups that contribute at least TOP_PERCENT of packets
    pkt_threshold = total_packets * constants.TOP_PERCENT
    
    print(f"\n[+] Threshold applied to packets: {pkt_threshold}")

    # Step 1: Build a global dictionary {sni: total_packets}
    sni_packet_count = {}
    for flow in final_flows:
        sni = flow.get('sni')
        if not sni:
            continue
        else:
            sni = sni.lower()
        exchanged = flow.get('exchanged_packets', [])

        pkt_count = 0
        for exch in exchanged:
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    pkt_count += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue

        sni_packet_count[sni] = sni_packet_count.get(sni, 0) + pkt_count

    # Keep only SNIs that exceed the packet threshold
    top_snis = {sni for sni, pkt in sni_packet_count.items() if pkt >= pkt_threshold}

    #print(f"\n[DEBUG] Top SNIs: {top_snis}")

    # Step 3: suffix maching ( subdomain )
    def is_sub_or_same_domain(sni, top_snis):

        for tsni in top_snis:
            if sni == tsni or tsni.endswith("." + sni):
                return True
        return False

    # Step 4: Filter groups and keep only top SNIs
    filtered_groups = []
    for group in groups:
        #print(f"\n{group.get("packets", 0)}\n")
        if group.get('packets', 0) >= pkt_threshold:
            snis = group.get('sni_list', [])
            top_group_snis = [sni for sni in snis if is_sub_or_same_domain(sni.lower(), top_snis)]

            new_group = group.copy()
            new_group["sni_list"] = top_group_snis
            filtered_groups.append(new_group)

    #print(f"[DEBUG] Final top groups: {filtered_groups}")
    return filtered_groups

# -------------------------------------------

def protocols_summary(flows):

    protocol_cou = Counter()

    for flow in flows:
        proto = flow.get('proto_field', "").lower()

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

def generate_rules(final_flows, output_file, protoname, sni_stats_file="tmp/sni_stats.txt", log_file_removed_flows="tmp/removed_flows.json", log_file_filtered_flows="tmp/filtered_flows.json", dataset_file="dataset/dataset.json", datasetTLD_file="dataset/datasetTLD.json", dataset_not_protocols_file="dataset/dataset_not_protocols_domains.json", ad_dataset_file="dataset/ad.json"):

    # load the main dataset of known domains
    with open(dataset_file, "r") as f:
        dataset = json.load(f)
    dataset_domains = {d.lower() for d in dataset.get('domains', [])}
    # sort dataset domains by length descending to match longer suffixes first
    sorted_dataset = sorted(dataset_domains, key=len, reverse=True)

    # load the ad dataset of known ad domains
    with open(ad_dataset_file, "r") as f:
        dataset = json.load(f)
    ad_dataset = {d.lower() for d in dataset.get('domains', [])}

    # load the TLD dataset
    with open(datasetTLD_file, "r") as f:
        datasetTLD = json.load(f)
    datasetTLD_domains = {d.lower() for d in datasetTLD.get('domains', [])}

    # load the dataset of known non-protocol domains
    with open(dataset_not_protocols_file, "r") as f:
        dataset_not_protocols = json.load(f)
    dataset_not_protocols_domains = {d.lower() for d in dataset_not_protocols.get('domains', [])}

    # --------------------------------

    # collect all SNIs seen in the final flows
    sni_list = [flow.get('sni') for flow in final_flows if 'sni' in flow and flow['sni']]
    unique_sni = sorted(set(sni_list))

    # print all SNIs detected in the flows
    config.log_message("\n\n>> All SNIs seen:\n\n", sni_stats_file)
    for sni in unique_sni:
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # --------------------------------

    # count the total number of packets in final_flows
    all_packets = 0

    for flow in final_flows:

        exchanged = flow.get('exchanged_packets', [])
        for exch in exchanged:
            if "<->" in exch:
                left, right = exch.split("<->")
                try:
                    all_packets += int(left.strip()) + int(right.strip())
                except ValueError:
                    continue

    print(f"\n[+] Total packets seen in the traffic: {all_packets}")

    # --------------------------------

    # SNIs filtered for debugging
    cleaned_snis = set()
    # groups grouped by (ja3s, ja4, certificate) keys
    groups = defaultdict(list)
    # raw groups before normalization
    raw_groups = []

    #print(f"\n[DEBUG] Starting with:\n\n{final_flows}\n")

    # remove flows with SNIs containing excluded words or present in the main dataset
    removed_flows = [
        flow for flow in final_flows
            if (flow.get('sni') and any(word in flow.get('sni').lower() for word in constants.EXCLUDE_WORDS))
            or (flow.get('sni') and flow.get('sni').lower() in sorted_dataset)
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

    config.log_message("\n\n>> Removed flows 2° filtering ( Remove known suffixes, not_protocols domains and ad domains ):\n\n", sni_stats_file)

    for flow in final_flows:

        sni = flow.get('sni')
        if sni:

            # initialize a processed SNI variable
            sni = sni.lower()
            sni_proc = sni

            #print(f"\n[DEBUG] Processing: {sni}")

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

                # 1) remove snis present in the main dataset and ad dataset
                remove_sni = False
                for d in sorted_dataset:
                    if sni_proc.endswith(d):
                        remove_sni = True
                        break
                if remove_sni:
                    config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                    removed_flows.append(flow)
                    continue
                
                for d in ad_dataset:
                    if sni_proc.endswith(d):
                        remove_sni = True
                        break
                if remove_sni:
                    config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                    removed_flows.append(flow)
                    continue

            #print(f"\n[DEBUG] Original SNI: {sni} → After removing dataset suffix: {sni_proc}")

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

            #print(f"\n[DEBUG] After removing numeric/short/TLD parts: {parts}")

            if not parts:
                config.log_message(f"   [+] [red]{sni}[/red]\n", sni_stats_file)
                removed_flows.append(flow)
                continue

            # add remaining SNI to the set
            cleaned_snis.add(sni)

        ja3s = flow.get('ja3s')
        ja4 = flow.get('ja4')
        certificate = {
            "certificate": flow.get('certificate'),
            "subject": flow.get('subject'),
            "issuer": flow.get('issuer'),
            "servernames": flow.get('servernames')
        }

        #print(f"\n[DEBUG] Flow → JA3S: {ja3s}, JA4: {ja4}, Cert: {certificate}")

        if not (ja3s or ja4 or certificate["certificate"] or certificate["subject"] or certificate["issuer"] or certificate["servernames"] or sni):
            removed_flows_ja.append(flow)
            #print(f"\n[DEBUG] Removed flow due to missing JA3S/JA4/Cert/SNI: {flow}")
            continue

        ja4 = normalize_ja4(ja4)

        # create a hashable key for the certificate dictionary
        cert_tuple = tuple(sorted(certificate.items()))
        key = (ja3s, ja4, cert_tuple)

        groups[key].append(flow)
    
    config.log_message(f"\n>> Removed flows after SNI filtering ( Remove known suffixes and not_protocols domains ) [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows, log_file_removed_flows)
    config.log_message(f"\n>> Removed flows after JA3S/JA4/Certificate filtering [DEBUG]:\n\n", log_file_removed_flows)
    config.log_message(removed_flows_ja, log_file_removed_flows)

    config.log_message(f"\n\n>> Remaining SNIs:\n\n", sni_stats_file)
    for sni in sorted(cleaned_snis):
        config.log_message(f"   [+] [green]{sni}[/green]\n", sni_stats_file)

    # --------------------------------

    for (ja3s, ja4, certificate), elements in groups.items():

        # --- Case 1: group with only SNI ( no JA3S, JA4, and no certificate ) ---
        if ja3s is None and ja4 is None and not any(certificate.values()):
            # create a separate object for each flow/SNI instead of aggregating
            for flow in elements:

                similar_count = flow.get('similar_flows_count', 0)
                exchanged = flow.get('exchanged_packets', [])
                # count total packets exchanged
                pkt = 0
                for exch in exchanged:
                    if "<->" in exch:
                        left, right = exch.split("<->")
                        try:
                            pkt += int(left.strip()) + int(right.strip())
                        except ValueError:
                            continue

                flow_sni = flow.get('sni')
                if flow_sni:
                    raw_groups.append({
                        "ja3s": ja3s,
                        "ja4": ja4,
                        "certificate": certificate,
                        "sni_list": [flow_sni],
                        "flow_count": similar_count,
                        "packets": pkt
                    })
        else:
            # --- Case 2: normal group with JA3S, JA4, or certificate ---
            # collect all unique SNI values
            sni_list = sorted({e.get('sni') for e in elements if e.get('sni')})

            # inizializza contatori totali
            total_flows = 0
            total_packets = 0

            # somma i flow_count e i pacchetti di tutti i flussi del group
            for flow in elements:
                total_flows += flow.get('similar_flows_count', 0)
                exchanged = flow.get('exchanged_packets', [])
                for exch in exchanged:
                    if "<->" in exch:
                        left, right = exch.split("<->")
                        try:
                            total_packets += int(left.strip()) + int(right.strip())
                        except ValueError:
                            continue

            raw_groups.append({
                "ja3s": ja3s,
                "ja4": ja4,
                "certificate": certificate,
                "sni_list": sni_list,
                "flow_count": total_flows,
                "packets": total_packets
            })

    for rc in raw_groups:
        rc["all_ja4_variants"] = find_ja4_by_suffix(rc.get("ja4"), final_flows)

    # merge groups based on SNI
    sni_to_use = group_sni.merge_flows(raw_groups)

    # save the raw groups
    with open("tmp/raw_groups.json", "w", encoding="utf-8") as f:
        json.dump(sni_to_use, f, indent=4)

    #print(f"\n[DEBUG] Merged Cluster: {sni_to_use}")

    if not constants.SHOW_NDPI_PROTOCOLS:
        sni_to_use = normalize_sni_groups(sni_to_use, sorted_dataset)

    # keep only flows that are not removed
    final_flows = [
        flow for flow in final_flows
        if (flow not in removed_flows) and (flow not in removed_flows_ja)
    ]

    config.clear_log(log_file_filtered_flows)
    config.log_message(final_flows, log_file_filtered_flows)

    # keep only the groups above the threshold (IMPORTANT)
    top_groups = filter_top_groups(final_flows, sni_to_use, all_packets)

    # save the final merged data to a JSON file
    with open("tmp/groups.json", "w", encoding="utf-8") as f:
        json.dump(top_groups, f, indent=4)

    # call classification on the cleaned and merged SNIs outputting to the specified file
    get_info.classify_domains(top_groups, output_file, protoname)

    return final_flows

#################################################################
# End of functions.py
#################################################################