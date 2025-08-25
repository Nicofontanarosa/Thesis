
import re
import json
import argparse
import os
import config

# Clear del terminale all'apertura
config.clear_terminal()

# parsing args
args = config.get_args()
input_file = args.input_file
output_file = args.output

# stampa dei file usati
config.print_files(input_file, output_file)

# lista dei protocolli da mantenere
protocols = config.PROTOCOLS
# lista degli IP da mantenere
# ips = config.PROTOCOLS

# -------------------------------------------

# lettura dei protocolli presenti nel file
all_protocols_in_file = set()
proto_regex = re.compile(r"\[proto: [0-9.]+/(.+?)\]")

# lettura degli IP presenti nel file
all_ip_in_file = set()
ip_regex = re.compile(r"\[IP: [0-9.]+/(.+?)\]")

with open(input_file, 'r') as fin:
    for line in fin:
        match_proto = proto_regex.search(line)
        if match_proto:
            all_protocols_in_file.add(match_proto.group(1))
        match_ip = ip_regex.search(line)
        if match_ip:
            all_ip_in_file.add(match_ip.group(1))
        
# stampa dei protocolli letti e filtrati
print("\nLista dei protocolli osservati:\n")
for proto in sorted(all_protocols_in_file):
    print(" -", proto)
print("\nLista dei protocolli analizzati:\n")
for proto in sorted(protocols):
    print(" -", proto)
print("\n!WARNING! PROTOCOLLI NON ANALIZZATI:\n")
for proto in sorted(all_protocols_in_file - protocols):
    print(" -", proto)

# stampa degli IP letti e filtrati
print("\nLista degli IP osservati:\n")
for ip in sorted(all_ip_in_file):
    print(" -", ip)
#print("\nLista degli IP analizzati:\n")
#for ip in sorted(ips):
#    print(" -", ip)

# -------------------------------------------

# grep -vP '(\[proto: \d+(\.\d+/.+?|/MSDO)\]|\[IP:.*(Google|Facebook|AmazonAWS|Azure).*\]|0\.0\.0\.0)|\[Plen Bins: (0,){47}0\]|\[proto: 91/TLS\](?!.*(Hostname/SNI:|ALPNs:|TLS Supported Versions:|JA3S:|JA4:|Risk:))'

# regex dinamiche
proto_pattern = r"\[proto: \d+/(" + "|".join(protocols) + r")\]"
#ip_pattern    = r"\[IP: 0/(" + "|".join(ips) + r")\]"
# regex per contare i flussi
proto_general_pattern = r"\[proto: [^\]]+\]"

# regex per righe JA Host Stats (solo IP host)
host_ip_only_pattern = re.compile(r"^\s*\d+\s+([0-9a-fA-F:.]+)\s+")
# regex per righe IPv6
ipv6_pattern = re.compile(r"\[[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\]")
# regex per flussi con IP 0.0.0.0
#match_ip_zero = re.compile(r"\[0\.0\.0\.0\]")
# regex per flussi privi di informazioni
plen_bins_empty_pattern = re.compile(r"\[Plen Bins: (0,){47}0\]")

# costruzione dinamica della regex
#pattern = re.compile(plen_bins_pattern + r".*" + proto_pattern + r".*" + ip_pattern)
pattern = re.compile(proto_pattern)
pattern_general = re.compile(proto_general_pattern)

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

# regex per rimuovere i campi [Goodput ratio: ...][...]                 [Goodput ratio: 66/83][4.53 sec]
goodput_pattern = re.compile(r"\[Goodput ratio: [^\]]+\]\[[^\]]*\]")
# regex per rimuovere i campi [bytes ratio: ...]                        [bytes ratio: -0.367 (Download)]
bytes_pattern = re.compile(r"\[bytes ratio: [^\]]+\]")
# regex per rimuovere i campi [Encrypted o ClearText]                   [Encrypted]
text_pattern = re.compile(r"\[(Encrypted|ClearText)\]")
# regex per rimuovere i campi [Confidence: ...]                         [Confidence: DPI]
confidence_pattern = re.compile(r"\[Confidence: [^]]+\]")
# regex per rimuovere i campi [FPC: ...]                                [FPC: 126/Google, Confidence: IP address]
fpc_pattern = re.compile(r"\[FPC: [^]]+\]")
# regex per rimuovere i campi [DPI packets: ...]                        [DPI packets: 7]
dpi_pattern = re.compile(r"\[DPI packets: [^]]+\]")
# regex per rimuovere i campi [IAT: ...]                                [IAT c2s/s2c min/avg/max/stddev: 0/0 197/186 3358/3418 715/697]
iat_pattern = re.compile(r"\[IAT [^]]+\]")
# regex per rimuovere i campi [Pkt Len ...]                             [Pkt Len c2s/s2c min/avg/max/stddev: 66/66 193/389 1454/1454 293/522]
pktlen_pattern = re.compile(r"\[Pkt Len [^]]+\]")
# regex per rimuovere i campi [Plen Bins ...]                           [Plen Bins: 15,18,15,9,3,6,3,0,0,0,0,0,3,3,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,18,0,0,0,0]
plen_bins_pattern = re.compile(r"\[Plen Bins: [^]]+\]")
# regex per rimuovere i campi [cat: ...]                                [cat: Advertisement/101]
cat_pattern = re.compile(r"\[cat: [^]]+\]")

flussi_lasciati = []
flussi_rimossi = []
flussi_vuoti_rimossi = []
flussi_IPv6_rimossi = []

# rimuovere flussi intermendi privi di handshake 11	TCP 192.168.80.96:63134 <-> 216.58.204.226:443 [proto: 91/TLS][IP: 126/Google][165 pkts/181934 bytes <-> 142 pkts/36253 bytes]

with open(input_file, 'r') as fin, open(output_file, 'w') as fout:

    for line in fin:
        line_stripped = line.strip()
        
        # prelevo l'IP dell'host
        if host_ip_only_pattern.match(line_stripped):
            flussi_lasciati.append(line)
            fout.write(line)
            continue
        
        # ignoro righe con IPv6
        if ipv6_pattern.search(line_stripped):
            flussi_IPv6_rimossi.append(line)
            continue

        # ignoro righe plain bins = 0
        if plen_bins_empty_pattern.search(line_stripped):
            flussi_vuoti_rimossi.append(line)
            continue

        # ignoro righe con ip 0.0.0.0
        #if match_ip_zero.search(line_stripped):
        #    flussi_rimossi.append(line)
        #    continue
            
        if pattern.search(line_stripped):

            # rimuovo i vari campi ...
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
            # aggiungo flusso a quelli tenuti
            flussi_lasciati.append(line)
            fout.write(clean_line)

        elif pattern_general.search(line_stripped):
            # aggiungo flussi a quelli rimossi
            flussi_rimossi.append(line)

# stampa riepilogo
print(f"\nFlussi letti: {len(flussi_lasciati) + len(flussi_rimossi) + len(flussi_vuoti_rimossi) + len(flussi_IPv6_rimossi)}")
print(f"Flussi tenuti: {len(flussi_lasciati)}")
print(f"Flussi rimossi: {len(flussi_rimossi) + len(flussi_vuoti_rimossi) + len(flussi_IPv6_rimossi)}")
print(f"  ├──Flussi generali rimossi: {len(flussi_rimossi)}")
print(f"  ├──Flussi vuoti rimossi: {len(flussi_vuoti_rimossi)}")
print(f"  └──Flussi IPv6 rimossi: {len(flussi_IPv6_rimossi)}")
