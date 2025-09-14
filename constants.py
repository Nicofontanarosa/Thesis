# command used to run nDPI and save output to JSON
# nDPI/example/ndpiReader -v 2 -i test/input.pcapng > test/output.json
# file with protocol IDs recognized by nDPI 
# nDPI/src/include/ndpi_protocol_ids.h
# file with protocol SNIs recognized by nDPI
# nDPI/src/lib/ndpi_content_match.c.inc
# file with protocol categories recognized by nDPI
# nDPI/src/include/ndpi_typedefs.h

# -------------------------------------------
# parameters used by all scripts 

# protocols to keep
PROTOCOLS = {"DNS", "TLS", "HTTP", "QUIC", "Unknown", "SMTP"}

# aggregation key: flows with identical values for all these fields are merged into a single entry
KEYS_BY_PROTOCOL = {
    "DNS": ["ip_source", "dns_ip", "sni"],
    "TLS": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "tls_version", "proto_field", "transport_protocol"],
    "HTTP": ["ip_source", "tcp_fingerprint", "ip_destination", "url", "user_agent", "content_type", "proto_field", "transport_protocol"],
    "QUIC": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "quic_version", "proto_field", "transport_protocol"],
    "Unknown": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "url", "user_agent", "content_type", "proto_field", "transport_protocol"],
    "SMTP": ["ip_source", "tcp_fingerprint", "ip_destination", "proto_field", "transport_protocol"]
}

# filter SNIs with more than 4 domain levels
SNI_MAX_DOMAIN = 4
# SNIs containing any word in this list will be excluded
EXCLUDE_WORDS = ["cdn", "amazonaws"]
# remove all SNI parts shorter than 3 characters
N_MIN = 3
# redacted organization names for whois
REDACTED_ORGS = {"redacted for privacy", "data redacted", "hidden", "not disclosed"}

# Minimum cosine similarity value: flows with similarity >= 10% are considered relevant
#THRESHOLD = 0.1  
# Minimum length of character n-grams used in TF-IDF
#N_MIN = 2
# Maximum length of character n-grams used in TF-IDF
#N_MAX = 3
