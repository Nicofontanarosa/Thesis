
# nDPI/example/ndpiReader -v 2 -i tesi/input.pcapng > tesi/output.json

# /home/keiyukensei/nDPI/src/include/ndpi_protocol_ids.h
# /home/keiyukensei/nDPI/src/lib/ndpi_content_match.c.inc
# nDPI/src/include/ndpi_typedefs.h

import os
import argparse

# protocols to keep
PROTOCOLS = {"DNS", "TLS", "HTTP", "QUIC", "Unknown", "SMTP"}
# key fields to keep in the output JSON
KEY = ("ip_source", "ip_destination", "port_destination", "proto_field", "transport_protocol",
    "sni", "tcp_fingerprint", "ja3s", "ja4", "alpn", "tls_versions", "tls_version", "cipher",
    "ech", "url", "user_agent", "content_type", "dns_ip")
# key to use for clustering flows
CLUSTER_KEY = ["ip_destination", "sni"]


def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_args():
    parser = argparse.ArgumentParser(description="Extract nDPI flows from a pcapng file and save to JSON")
    parser.add_argument("input_file", help="Input file in pcapng format")
    parser.add_argument("-o", "--output", default="output_flows.json", help="Json output file (default: output_flows.json)")
    return parser.parse_args()

def print_files(input_file, output_file):
    print(f"\nInput file: {input_file}")
    print(f"Output file: {output_file}\n")






[9/3, 1:36 AM] KeiyuKensei: from rapidfuzz import fuzz, process

# domini da clusterizzare
domains = [
    "youtube.come",
    "maps.com",
    "googleservice.maps.com",
    "vinted.com",
    "appvin.com",
    "applevin.com"
]

# parole chiave principali
keywords = ["youtube", "maps", "googleservice", "vinted"]

clusters = {k: [] for k in keywords}
clusters["Other"] = []

# soglia di similarità
THRESHOLD = 80

for domain in domains:
    best_match, score, _ = process.extractOne(domain, keywords, scorer=fuzz.partial_ratio)
    if score >= THRESHOLD:
        clusters[best_match].append(domain)
    else:
        clusters["Other"].append(domain)

# risultato
for k, v in clusters.items():
    if v:
        print(f"{k}: {v}")
[9/3, 8:26 AM] KeiyuKensei: from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

domains = [
    "youtube.come",
    "maps.com",
    "googleservice.maps.com",
    "vinted.com",
    "appvin.com",
    "applevin.com"
]

# 1. Trasformo i domini in n-grammi di caratteri
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
X = vectorizer.fit_transform(domains)

# 2. Numero cluster (puoi stimarlo o usare silhouette score)
k = 4
kmeans = KMeans(n_clusters=k, random_state=42, n_init="auto")
labels = kmeans.fit_predict(X)

# 3. Raggruppo domini per cluster
clusters = {}
for domain, label in zip(domains, labels):
    clusters.setdefault(label, []).append(domain)

for label, group in clusters.items():
    print(f"Cluster {label}: {group}")
[9/3, 8:26 AM] KeiyuKensei: from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering

vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
X = vectorizer.fit_transform(domains).toarray()

clustering = AgglomerativeClustering(
    n_clusters=None,       # nessun numero fisso
    distance_threshold=1.0 # soglia (da regolare)
)
labels = clustering.fit_predict(X)

clusters = {}
for domain, label in zip(domains, labels):
    clusters.setdefault(label, []).append(domain)

for label, group in clusters.items():
    print(f"Cluster {label}: {group}")