
#################################################################
# File: extract_tls_ja3_sni.py
# Purpose: Extract JA3/JA4 fingerprints and SNI values from a PCAP file
# using tshark, then group (cluster) them by (JA4, JA3S) pairs.
#################################################################

import subprocess
import json
from collections import defaultdict

# -------------------------------------------

def normalize_ja4(ja4):
    
    # Normalize the JA4 fingerprint by removing the initial prefix
    if not ja4:
        return ""
    return ja4.split("_", 1)[-1] if "_" in ja4 else ja4

def extract_tls_clusters(pcap_file, out_file):
    
    # Fields to extract from each TLS handshake
    fields = [
        "-e", "tcp.stream",
        "-e", "tls.handshake.ja4",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.extensions_server_name"
    ]

    # Build the tshark command:
    # -r: read the input PCAP
    # -Y: apply a display filter (TLS handshakes only)
    # -T fields: output selected fields in CSV-like format
    # -E separator/quote: configure output formatting
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "tls.handshake",
        "-T", "fields",
        "-E", "separator=,", "-E", "quote=d"
    ] + fields
    # Run tshark and capture the output
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")

    # Dictionary mapping each TCP stream to its extracted attributes
    streams = {}
    # Parse each line of tshark output
    for line in lines:
        if not line.strip():
            continue
        # Split CSV line and remove quotes
        parts = [x.strip('"') for x in line.split(",")]
        while len(parts) < 4:
            parts.append("")

        stream, ja4, ja3s, sni = parts
        ja4 = normalize_ja4(ja4)

        # Initialize the stream entry if it doesn’t exist
        if stream not in streams:
            streams[stream] = {
                "ja4": ja4,
                "ja3s": ja3s,
                "sni_list": set()
            }

        # Update JA4, JA3S, and add any new SNI
        if ja4:
            streams[stream]["ja4"] = ja4
        if ja3s:
            streams[stream]["ja3s"] = ja3s
        if sni:
            streams[stream]["sni_list"].add(sni)

    # === Build final clusters grouped by (JA4, JA3S) ===
    final_clusters = defaultdict(set)

    for s in streams.values():
        ja4, ja3s = s["ja4"], s["ja3s"]
        if not ja4 or not ja3s:
            continue
        # Merge all SNI values from streams that share the same (JA4, JA3S)
        final_clusters[(ja4, ja3s)].update(s["sni_list"])

    # Create a list of cluster dictionaries for JSON serialization
    result = []
    for (ja4, ja3s), snis in final_clusters.items():
        result.append({
            "ja4": ja4,
            "ja3s": ja3s,
            "sni_list": sorted(list(snis))
        })

    # Sort clusters by the number of associated SNIs
    result = sorted(result, key=lambda x: len(x["sni_list"]), reverse=True)

    # Save the result to JSON file
    with open(out_file, "w") as f:
        json.dump(result, f, indent=4)

#################################################################
# End of extract_tls_ja3_sni.py
#################################################################