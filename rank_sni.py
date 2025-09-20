
#################################################################
# File: rank_sni.py to compute and display SNI rankings
#################################################################

import json
import config
from datetime import datetime

def rank_sni(flows, times_file, log_file_time, log_file_rank):

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
    config.log_message(f"\n>> Temporal ranking:\n\n {sni_times}", log_file_time)    
    for sni in temporal_ranking:
        ts = sni_stats[sni]['first_seen']
        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
        config.log_message(f" + SNI: {sni}\n  + first_seen:{ts_str}\n", log_file_time)

    # Print frequency ranking
    config.log_message(f"\n>> Frequency ranking:\n\n {sni_times}", log_file_rank)
    for sni in frequency_ranking:
        config.log_message(f" + SNI: {sni}\n  + count: {sni_stats[sni]['count']}", log_file_rank)