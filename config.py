
# nDPI/example/ndpiReader -v 2 -i tesi/input.pcapng > tesi/output.json

# /home/keiyukensei/nDPI/src/include/ndpi_protocol_ids.h
# /home/keiyukensei/nDPI/src/lib/ndpi_content_match.c.inc
# nDPI/src/include/ndpi_typedefs.h

import argparse

# protocols to keep
PROTOCOLS = {"DNS", "TLS", "HTTP", "QUIC", "Unknown", "SMTP"}

# Aggregation key: flows with identical values for all these fields are merged into a single entry
KEYS_BY_PROTOCOL = {
    "DNS": ["ip_source", "dns_ip"],
    "TLS": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "tls_version"],
    "HTTP": ["ip_source", "tcp_fingerprint", "ip_destination", "url", "user_agent", "content_type"],
    "QUIC": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "quic_version"],
    "Unknown": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "url", "user_agent", "content_type"],
    "SMTP": ["ip_source", "tcp_fingerprint", "ip_destination"]
}

KEY = ("ip_source", "ip_destination", "port_destination", "proto_field", "transport_protocol",
    "sni", "tcp_fingerprint", "ja3s", "ja4", "tls_version", "quic_version", "url", "user_agent", "content_type", "dns_ip")

# Minimum cosine similarity value: flows with similarity >= 10% are considered relevant
THRESHOLD = 0.1  
# Minimum length of character n-grams used in TF-IDF
N_MIN = 2
# Maximum length of character n-grams used in TF-IDF
N_MAX = 3

# -------------------------------------------

def get_args():
    parser = argparse.ArgumentParser(description="Extract nDPI flows from a pcapng file and save to JSON")
    parser.add_argument("input_file", help="Input file in pcapng format")
    parser.add_argument("-o", "--output", default="output_flows.json", help="Json output file (default: output_flows.json)")
    return parser.parse_args()

def print_files(input_file, output_file):
    print(f"\nInput file: {input_file}")
    print(f"Output file: {output_file}\n")

# -------------------------------------------