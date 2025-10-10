
#################################################################
# File: rank_sni.py to compute and display SNI rankings
#################################################################

import json
import config
from datetime import datetime
import constants

def filter_sni_to_use(sni_to_use, intersection):

    def matches_intersection(sni, intersection):
        for base in intersection:
            # Caso 1: identici
            if sni == base:
                return True
            # Caso 2: sni è sottodominio di base
            if sni.endswith("." + base):
                return True
            # Caso 3: base è sottodominio di sni
            if base.endswith("." + sni):
                return True
        return False

    # Filtro in place
    for cluster in sni_to_use:
        cluster["sni_list"] = [
            sni for sni in cluster.get("sni_list", [])
            if matches_intersection(sni, intersection)
        ]

    # Rimuovo cluster vuoti
    sni_to_use[:] = [c for c in sni_to_use if c["sni_list"]]
    print(f"\nFiltered clusters to classify {sni_to_use}\n")

def rank_sni(flows, times_file, sni_to_use, log_file_time, log_file_rank, log_file_intersection):

    config.clear_log(log_file_time)
    config.clear_log(log_file_rank)
    config.clear_log(log_file_intersection)

    # Dictionary to store statistics for each SNI
    sni_stats = {}   
    # Dictionary to map each SNI to its earliest observed timestamp
    sni_times = {} 
    # List to preserve the order in which SNIs first appear in the flows  
    seen_order = []

    # --- Load timestamps from file ---
    with open(times_file, "r") as f:
        for line in f:
            try:
                rec = json.loads(line)
                # Extract SNI or domain name
                sni = rec.get("ndpi", {}).get("hostname") or rec.get("ndpi", {}).get("domainname")
                if not sni:
                    continue
                ts = rec.get("first_seen")
                # Keep the earliest timestamp for each SNI
                if sni not in sni_times or (ts is not None and ts < sni_times[sni]):
                    sni_times[sni] = ts
            except Exception:
                continue

    # --- Analyze the flows ---
    for f in flows:
        sni = f.get("sni")
        if not sni:
            continue

        # Weight: number of similar flows, default 1
        weight = f.get("similar_flows_count", 1)

        # Initialize entry if SNI is new
        if sni not in sni_stats:
            sni_stats[sni] = {"count": 0, "first_seen": sni_times.get(sni)}
            seen_order.append(sni)

        # Increase count by weight
        sni_stats[sni]["count"] += weight

    # Ranking 1: order by first appearance
    temporal_ranking = sorted(seen_order, key=lambda x: (sni_stats[x]["first_seen"] or float("inf")))

    # Ranking 2: order by frequency (most seen first)
    frequency_ranking = sorted(sni_stats.keys(), key=lambda x: sni_stats[x]["count"], reverse=True)

    # Print temporal ranking
    config.log_message(f">> Temporal ranking:\n\n", log_file_time)    
    for sni in temporal_ranking:
        ts = sni_stats[sni]['first_seen']
        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
        config.log_message(f"\n + SNI: {sni}\n  + first_seen:{ts_str}\n", log_file_time)

    # Print frequency ranking
    config.log_message(f">> Frequency ranking:\n\n", log_file_rank)
    for sni in frequency_ranking:
        config.log_message(f"\n + SNI: {sni}\n  + count: {sni_stats[sni]['count']}\n", log_file_rank)

    # --- Intersection of top 80% ---
    take_ratio = constants.TOP_RATIO

    n_temp = int(len(temporal_ranking) * take_ratio)
    n_freq = int(len(frequency_ranking) * take_ratio)

    top_temporal = set(temporal_ranking[:n_temp])
    top_frequency = set(frequency_ranking[:n_freq])
    sni_from_use = {sni for cluster in sni_to_use for sni in cluster.get("sni_list", [])}

    # Intersezione e filtro con sni_to_use
    # intersezione considerando anche sottodomini
    intersection = set()
    for sni in (top_temporal & top_frequency):
        for base in sni_from_use:
            if sni == base or sni.endswith("." + base):
                intersection.add(sni)
                break

    # Scrivi su file
    config.log_message(f">> Intersection of top {int(take_ratio*100)}% temporal & frequency rankings:\n\n", log_file_intersection)
    for sni in intersection:
        config.log_message(f" + SNI: {sni}\n", log_file_intersection)

    # --- Filtra sni_to_use in place ---
    filter_sni_to_use(sni_to_use, intersection)

#################################################################
# End of rank_sni.py
#################################################################