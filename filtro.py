
import re
import json
# my file
import config

# parsing args
args = config.get_args()
input_file = args.input_file
output_file = args.output

# print files used
config.print_files(input_file, output_file)

# protocols to keep
protocols = config.PROTOCOLS

# -------------------------------------------

# reading all protocols present in the file
all_protocols_in_file = set()
# regex to extract protocol names
proto_regex = re.compile(r"\[proto:\s*[0-9.]+/([^.\]]+)")
# reading all IPs present in the file
all_ip_in_file = set()
# regex to extract IP names
ip_regex = re.compile(r"\[IP: [0-9.]+/(.+?)\]")

# 1° file open
with open(input_file, 'r') as fin:
    for line in fin:
        match_proto = proto_regex.search(line)
        if match_proto:
            all_protocols_in_file.add(match_proto.group(1).strip())
        match_ip = ip_regex.search(line)
        if match_ip:
            all_ip_in_file.add(match_ip.group(1))
        
# printing protocols read and filtered
print("Lists of protocols read:\n")
for proto in sorted(all_protocols_in_file):
    print(" -", proto)
print("\nLists of protocols analyzed:\n")
for proto in sorted(protocols):
    print(" -", proto)
print("\n!WARNING! PROTOCOLLS NOT ANALYZED:\n")
for proto in sorted(all_protocols_in_file - protocols):
    print(" -", proto)
# printing IPs read
print("\nList of IP read:\n")
for ip in sorted(all_ip_in_file):
    print(" -", ip)
    
# -------------------------------------------

# 1° version of the filtering script using regex
# grep -vP '(\[proto: \d+(\.\d+/.+?|/MSDO)\]|\[IP:.*(Google|Facebook|AmazonAWS|Azure).*\]|0\.0\.0\.0)|\[Plen Bins: (0,){47}0\]|\[proto: 91/TLS\](?!.*(Hostname/SNI:|ALPNs:|TLS Supported Versions:|JA3S:|JA4:|Risk:))'

# dynamic construction of the regex
# regex to match protocols to keep nDPI not recognized
# pattern_all = re.compile(r"\[proto: \d+/(" + "|".join(protocols) + r")\]")
# regex to match protocols to keep
pattern = re.compile(r"\[proto:\s*(?:\d+(?:\.\d+)?/)?(" + "|".join(protocols) + r")[^\]]*\]")

# regex to match any protocol
pattern_general = re.compile(r"\[proto: [^\]]+\]")
# regex to match lines with only the host IP
host_ip_only_pattern = re.compile(r"^\s*\d+\s+([0-9a-fA-F:.]+)\s+")
# regex to match lines with IPv6 addresses
ipv6_pattern = re.compile(r"\[[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\]")
# regex to match lines with plen bins all zero
plen_bins_empty_pattern = re.compile(r"\[Plen Bins: (0,){47}0\]")
# regex to match incomplete TLS flows (no handshake)
tls_incomplete_pattern = re.compile(r"^\s*\d+\s+(?:TCP|UDP)\s+\d+\.\d+\.\d+\.\d+:\d+\s+(?:<->|->|<-)\s+\d+\.\d+\.\d+\.\d+:\d+\s+\[proto:\s*\d+/(?:TLS|QUIC)\]\[IP:\s*[^\]]+\]\[(\d+)\s+pkts\s*[^\]]+\]")

# 1° version of the filtering script using regex
#sed -E 's/\[Goodput ratio: [^]]+\]\[[^]]+\]//g; 
#s/\[bytes ratio: [^]]+\]//g;
#s/\[(Encrypted|ClearText)\]//g;
#s/\[Confidence: [^]]+\]//g;
#s/\[FPC: [^]]+\]//g;
#s/\[DPI packets: [^]]+\]//g;
#s/\[IAT [^]]+\]//g;
#s/\[Pkt Len [^]]+\]//g';
#s/\[DNS Id: [^]]+\]//g'
#s/\[Plen Bins: [^]]+\]//g
#s/\[PLAIN TEXT \([^]]+\)\]//g;

# regex to remove the fields [Goodput ratio: ...][...]                  [Goodput ratio: 66/83][4.53 sec]
goodput_pattern = re.compile(r"\[Goodput ratio: [^\]]+\]\[[^\]]*\]")
# regex to remove the fields [bytes ratio: ...]                         [bytes ratio: 181934/365756]
bytes_pattern = re.compile(r"\[bytes ratio: [^\]]+\]")
# regex to remove the fields [Encrypted] or [ClearText]                 [Encrypted]
text_pattern = re.compile(r"\[(Encrypted|ClearText)\]")
# regex to remove the fields [Safari] or [Chrome]                       [Safari]
host_pattern = re.compile(r"\[(Safari|Chrome)\]")
# regex to remove the fields [Confidence: ...]                          [Confidence: DPI]
confidence_pattern = re.compile(r"\[Confidence: [^]]+\]")
# regex to remove the fields [FPC: ...]                                 [FPC: 126/Google, Confidence: IP address]                             
fpc_pattern = re.compile(r"\[FPC: [^]]+\]")
# regex to remove the fields [DPI packets: ...]                         [DPI packets: 7]
dpi_pattern = re.compile(r"\[DPI packets: [^]]+\]")
# regex to remove the fields [IAT ...]                                  [IAT c2s/s2c min/avg/max/stddev: 0/0 197/186 3358/3418 715/697]
iat_pattern = re.compile(r"\[IAT [^]]+\]")
# regex to remove the fields [Pkt Len ...]                              [Pkt Len c2s/s2c min/avg/max/stddev: 66/66 193/389 1454/1454 293/522]
pktlen_pattern = re.compile(r"\[Pkt Len [^]]+\]")
# regex to remove the fields [Plen Bins: ...]                           [Plen Bins: 15,18,15,9,3,6,3,0,0,0,0,0,3,3,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,18,0,0,0,0]
plen_bins_pattern = re.compile(r"\[Plen Bins: [^]]+\]")
# regex to remove the fields [cat: ...]                                 [cat: Advertisement/101]
cat_pattern = re.compile(r"\[cat: [^]]+\]")

# -------------------------------------------

keep_flows = []
remove_flows = []
empty_flows = []
ipv6_flows = []
incomplete_tls_flows = []

# 2° - 3° file open
with open(input_file, 'r') as fin, open(output_file, 'w') as fout:

    for line in fin:
        line_stripped = line.strip()
        
        # check for lines with only the host IP
        if host_ip_only_pattern.match(line_stripped):
            keep_flows.append(line)
            fout.write(line)
            continue
        
        # check for lines with IPv6 addresses
        if ipv6_pattern.search(line_stripped):
            ipv6_flows.append(line)
            continue

        # check for lines with plen bins all zero
        if plen_bins_empty_pattern.search(line_stripped):
            empty_flows.append(line)
            continue
            
        if pattern.search(line_stripped):

            # remove unwanted fields
            clean_line = goodput_pattern.sub("", line)
            clean_line = bytes_pattern.sub("", clean_line)
            clean_line = text_pattern.sub("", clean_line)
            clean_line = confidence_pattern.sub("", clean_line)
            clean_line = fpc_pattern.sub("", clean_line)
            clean_line = dpi_pattern.sub("", clean_line)
            clean_line = iat_pattern.sub("", clean_line)
            clean_line = pktlen_pattern.sub("", clean_line)
            clean_line = plen_bins_pattern.sub("", clean_line)
            clean_line = cat_pattern.sub("", clean_line)
            clean_line = host_pattern.sub("", clean_line)

            # check for incomplete TLS flows
            if tls_incomplete_pattern.fullmatch(clean_line.strip()):
                incomplete_tls_flows.append(line)
                continue

            # add good flows
            keep_flows.append(line)
            fout.write(clean_line)

        elif pattern_general.search(line_stripped):
            # remove flows matching general protocol pattern
            remove_flows.append(line)

# Print summary
print(f"\nFlows read: {len(keep_flows) + len(remove_flows) + len(empty_flows) + len(ipv6_flows) + len(incomplete_tls_flows)}")
print(f"Flows kept: {len(keep_flows)}")
print(f"Flows removed: {len(remove_flows) + len(empty_flows) + len(ipv6_flows) + len(incomplete_tls_flows)}")
print(f"  ├── General flows removed: {len(remove_flows)}")
print(f"  ├── Empty flows removed: {len(empty_flows)}")
print(f"  ├── IPv6 flows removed: {len(ipv6_flows)}")
print(f"  └── Incomplete TLS flows removed: {len(incomplete_tls_flows)}")
