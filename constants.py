
# command used to run nDPI and save output to JSON
# nDPI/example/ndpiReader -v 2 -i test/input.pcapng > test/output.json
# nDPI/example/ndpiReader -k test/output_k.json -i test/input.pcapng
# file with protocol IDs recognized by nDPI 
# nDPI/src/include/ndpi_protocol_ids.h
# file with protocol SNIs recognized by nDPI
# nDPI/src/lib/ndpi_content_match.c.inc
# file with protocol categories recognized by nDPI
# nDPI/src/include/ndpi_typedefs.h

# -------------------------------------------
# parameters used by all scripts 

# remove all SNI domains shorter than 3 characters
N_MIN = 3

# show nDPI protocol in the output
SHOW_NDPI_PROTOCOLS = False

# percentage of total packets to use as threshold for top SNI selection
TOP_PERCENT = 0.2

# protocols to keep
PROTOCOLS = {"TLS", "HTTP", "HTTP_Connect", "HTTP.WebSocket", "QUIC"}

# aggregation key: flows with identical values for all these fields are merged into a single entry
KEYS_BY_PROTOCOL = {
    "TLS": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "tls_version", "proto_field", "transport_protocol"],
    "HTTP": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "url", "user_agent", "proto_field", "transport_protocol"],
    "QUIC": ["ip_source", "tcp_fingerprint", "ip_destination", "sni", "ja3s", "ja4", "quic_version", "proto_field", "transport_protocol"]
}

# filter SNIs with more than 4 domain levels
SNI_MAX_DOMAIN = 4

# SNIs containing any word in this list will be excluded
EXCLUDE_WORDS = [
    "cdn",
    "amazonaws",
    "akamaiedge",
    "akamaitechnologies",
    "akamaizer",
    "akamaicdn",
    "cloudfront",
    "cloudflare",
    "fastly",
    "edgekey",
    "edgesuite",
    "azureedge",
    "stackpath",
    "cdnetworks",
    "incap",
    "gcore",
    "kxcdn",
    "chinacache",
    "llnwd",
    "akamaitechnologies",
    "akamai",
    "vo.msecnd",
    "netdna",
    "fastly"
]

# -------------------------------------------