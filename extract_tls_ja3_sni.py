#!/usr/bin/env python3
import subprocess
import sys
import json
from collections import defaultdict

def normalize_ja4(ja4):
    
    if not ja4:
        return ""
    return ja4.split("_", 1)[-1] if "_" in ja4 else ja4

def extract_tls_clusters(pcap_file, out_file):
    # campi da estrarre: tcp.stream + ja4, ja3s, sni
    fields = [
        "-e", "tcp.stream",
        "-e", "tls.handshake.ja4",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.extensions_server_name"
    ]

    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "tls.handshake",
        "-T", "fields",
        "-E", "separator=,", "-E", "quote=d"
    ] + fields

    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")

    #print(f"Estratti {lines}")

    # flussi per stream
    streams = {}

    for line in lines:
        if not line.strip():
            continue
        parts = [x.strip('"') for x in line.split(",")]
        while len(parts) < 4:
            parts.append("")

        stream, ja4, ja3s, sni = parts
        ja4 = normalize_ja4(ja4)

        if stream not in streams:
            streams[stream] = {
                "ja4": ja4,
                "ja3s": ja3s,
                "sni_list": set()
            }

        if ja4:
            streams[stream]["ja4"] = ja4
        if ja3s:
            streams[stream]["ja3s"] = ja3s
        if sni:
            streams[stream]["sni_list"].add(sni)

    # === CLUSTER FINALE PER (ja4, ja3s) ===
    final_clusters = defaultdict(set)

    for s in streams.values():
        ja4, ja3s = s["ja4"], s["ja3s"]
        if not ja4 or not ja3s:
            continue
        # aggiungo tutte le SNI del flusso al cluster
        final_clusters[(ja4, ja3s)].update(s["sni_list"])

    # crea lista finale
    result = []
    for (ja4, ja3s), snis in final_clusters.items():
        result.append({
            "ja4": ja4,
            "ja3s": ja3s,
            "sni_list": sorted(list(snis))
        })

    # ordina per numero di SNI (opzionale)
    result = sorted(result, key=lambda x: len(x["sni_list"]), reverse=True)

    # salva JSON
    with open(out_file, "w") as f:
        json.dump(result, f, indent=4)

    print(f"Fatto! Output in {out_file}")
