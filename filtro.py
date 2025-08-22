
import re
import json
import argparse
import os

# Clear del terminale all'apertura
os.system('cls' if os.name == 'nt' else 'clear')

# Parser per argomenti da linea di comando
parser = argparse.ArgumentParser(description="Estrazione flussi da output nDPI")
parser.add_argument("input_file", help="File di input con i flussi nDPI")
parser.add_argument("-o", "--output", default="output_flussi.json", help="File JSON di output (default: output_flussi.json)")
args = parser.parse_args()

input_file = args.input_file
output_file = args.output

# stampa dei file usati
print(f"\nFile di input: {input_file}")
print(f"File di output: {output_file}\n")

# lista dei protocolli da mantenere
protocols = {"DNS", "TLS", "HTTP", "QUIC", "Unknown"}
# lista degli IP da mantenere
ips = {"Unknown"}

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

# stampa degli IP letti e filtrati
print("\nLista degli IP osservati:\n")
for ip in sorted(all_ip_in_file):
    print(" -", ip)
print("\nLista degli IP analizzati:\n")
for ip in sorted(ips):
    print(" -", ip)

# -------------------------------------------

# grep -vP '(\[proto: \d+(\.\d+/.+?|/MSDO)\]|\[IP:.*(Google|Facebook|AmazonAWS|Azure).*\]|0\.0\.0\.0)|\[Plen Bins: (0,){47}0\]|\[proto: 91/TLS\](?!.*(Hostname/SNI:|ALPNs:|TLS Supported Versions:|JA3S:|JA4:|Risk:))'

# regex dinamiche
proto_pattern = r"\[proto: \d+/(" + "|".join(protocols) + r")\]"
ip_pattern    = r"\[IP: 0/(" + "|".join(ips) + r")\]"
# regex per flussi privi di informazioni
plen_bins_pattern = r"^(?!.*\[Plen Bins: (0,){47}0\])"
# regex per contare i flussi
proto_general_pattern = r"\[proto: [^\]]+\]"

# costruzione dinamica della regex
pattern = re.compile(plen_bins_pattern + r".*" + proto_pattern + r".*" + ip_pattern)
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
#s/\[Plen Bins: [^]]+\]//g;

# regex per rimuovere i campi [Goodput ratio: ...][...]
goodput_pattern = re.compile(r"\[Goodput ratio: [^\]]+\]\[[^\]]*\]")
# regex per rimuovere i campi [bytes ratio: ...]
bytes_pattern = re.compile(r"\[bytes ratio: [^\]]+\]")
# regex per rimuovere i campi [Encrypted o ClearText]
text_pattern = re.compile(r"\[(Encrypted|ClearText)\]")
# regex per rimuovere i campi [Confidence: ...]
confidence_pattern = re.compile(r"\[Confidence: [^]]+\]")
# regex per rimuovere i campi [FPC: ...]
fpc_pattern = re.compile(r"\[FPC: [^]]+\]")
# regex per rimuovere i campi [DPI packets: ...]
dpi_pattern = re.compile(r"\[DPI packets: [^]]+\]")
# regex per rimuovere i campi [IAT: ...]
iat_pattern = re.compile(r"\[IAT [^]]+\]")
# regex per rimuovere i campi [Pkt Len ...]
pktlen_pattern = re.compile(r"\[Pkt Len [^]]+\]")
# regex per rimuovere i campi [Pkt Len ...]
plen_bins_pattern = re.compile(r"\[Plen Bins: [^]]+\]")

flussi_lasciati = []
flussi_rimossi = []

# regex per righe JA Host Stats (solo IP host)
host_ip_only_pattern = re.compile(r"^\s*\d+\s+([0-9a-fA-F:.]+)\s+")
# regex per righe IPv6
ipv6_pattern = re.compile(r"\[[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\]")

with open(input_file, 'r') as fin, open(output_file, 'w') as fout:
    for line in fin:
        line_stripped = line.strip()
        # prima controllo se è riga host puro
        if host_ip_only_pattern.match(line_stripped):
            flussi_lasciati.append(line)
            fout.write(line)
            continue
        # ignoro righe che iniziano con IPv6
        if ipv6_pattern.search(line_stripped):
            flussi_rimossi.append(line)
            continue
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
            flussi_lasciati.append(line)
            fout.write(clean_line)
        elif pattern_general.search(line_stripped):
            flussi_rimossi.append(line)

# stampa riepilogo
print(f"\nFlussi letti: {len(flussi_lasciati) + len(flussi_rimossi)}")
print(f"Flussi tenuti: {len(flussi_lasciati)}")
print(f"Flussi rimossi: {len(flussi_rimossi)}")
