
import re
import json
import argparse
from collections import Counter
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

flussi = []
counter = 1

with open(input_file, 'r') as f_in:
    for riga in f_in:
        riga = riga.strip()
        # if not riga or not re.search(r"\d+\.\d+\.\d+\.\d+:\d+", riga):
        if not riga or not re.search(r"\d+\.\d+\.\d+\.\d+", riga):
            continue

        flusso = {"id": counter, "riga_grezza": riga}

        # Host
        match_ip_only = re.match(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s*$", riga)
        if match_ip_only:
            flusso["ip_host"] = match_ip_only.group(1)
            flussi.append(flusso)
            counter += 1
            continue

        # IP
        match_ip_field = re.search(r"\[IP:\s*([^\]]+)\]", riga)
        if match_ip_field:
            flusso["ip_field"] = match_ip_field.group(1)

        # Protocollo Trasporto
        match_transport = re.search(r"^\s*\d+\s+([A-Za-z0-9]+)", riga)
        if match_transport:
            flusso["protocollo_trasporto"] = match_transport.group(1)

        # Protocollo
        match_proto = re.search(r"\[proto:\s*([\d\.]+\/[^\]]+)\]", riga)
        if match_proto:
            flusso["proto_field"] = match_proto.group(1)
        
            if "DNS" in match_proto.group(1):
                # DNS IP
                match_dns_ip = re.search(r"\]\[([\d]+\.[\d]+\.[\d]+\.[\d]+)\]", riga)
                if match_dns_ip:
                    flusso["dns_ip"] = match_dns_ip.group(1)

                # DNS ID
                match_dns_id = re.search(r"\[DNS Id:\s*([^\]]+)\]", riga)
                if match_dns_id:
                    flusso["dns_id"] = match_dns_id.group(1)

            if "HTTP" in match_proto.group(1):
                # URL
                match_url = re.search(r"\[URL:\s*([^\]]+)\]", riga)
                if match_url:
                    flusso["url"] = match_url.group(1)

                # Content-Type
                match_ct = re.search(r"\[Content-Type:\s*([^\]]+)\]", riga)
                if match_ct:
                    flusso["content_type"] = match_ct.group(1)

                # User-Agent
                match_ua = re.search(r"\[User-Agent:\s*([^\]]+)\]", riga)
                if match_ua:
                    flusso["user_agent"] = match_ua.group(1)

                # Status code
                match_status = re.search(r"\[StatusCode:\s*([^\]]+)\]", riga)
                if match_status:
                    flusso["status_code"] = match_status.group(1)

            if "TLS" in match_proto.group(1):
                # ALPN
                match_alpn = re.search(r"\[\(Advertised\) ALPNs:\s*([^\]]+)\]", riga)
                if match_alpn:
                    flusso["alpn"] = match_alpn.group(1)

                # TLS Versions
                match_tls = re.search(r"\[TLS Supported Versions:\s*([^\]]+)\]", riga)
                if match_tls:
                    flusso["tls_versions"] = match_tls.group(1)

                # Versione TLS effettiva
                match_tls_version = re.search(r"\[(TLSv[0-9.]+)\]", riga)
                if match_tls_version:
                    flusso["tls_version"] = match_tls_version.group(1)

                # JA3/JA4
                match_ja3 = re.search(r"\[JA3S:\s*([^\]]+)\]", riga)
                if match_ja3:
                    flusso["ja3s"] = match_ja3.group(1)

                match_ja4 = re.search(r"\[JA4:\s*([^\]]+)\]", riga)
                if match_ja4:
                    flusso["ja4"] = match_ja4.group(1)

                # Client/Browser/OS
                match_client = re.search(r"\[([A-Za-z0-9\s\-_]+)\]", riga)
                if match_client:
                    flusso["client"] = match_client.group(1)

                # Cipher usato
                match_cipher = re.search(r"\[Cipher:\s*([^\]]+)\]", riga)
                if match_cipher:
                    flusso["cipher"] = match_cipher.group(1)

        # Plain Text
        match_plain = re.search(r"\[PLAIN TEXT\s*\(([^)]+)\)\]", riga)
        if match_plain:
            flusso["plain_text"] = match_plain.group(1)

        # SNI / Hostname
        match_sni = re.search(r"\[Hostname/SNI:\s*([^\]]+)\]", riga)
        if match_sni:
            flusso["sni"] = match_sni.group(1)
    
        # IP e porte
        match_ip = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)", riga)
        if match_ip:
            flusso["ip_sorgente"] = match_ip.group(1)
            flusso["porta_sorgente"] = match_ip.group(2)
            flusso["ip_destinazione"] = match_ip.group(3)
            flusso["porta_destinazione"] = match_ip.group(4)

        # Numero pacchetti sorgente e destinazione
        match_pkts = re.search(r"\[(\d+)\s+pkts/[^<]+<->\s+(\d+)\s+pkts/", riga)
        if match_pkts:
            flusso["pkts_sorgente"] = int(match_pkts.group(1))
            flusso["pkts_destinazione"] = int(match_pkts.group(2))

        # Fingerprint TCP
        match_tcp_fp = re.search(r"\[TCP Fingerprint:\s*([^\]]+)\]", riga)
        if match_tcp_fp:
            flusso["tcp_fingerprint"] = match_tcp_fp.group(1)

        # Categoria
        match_cat = re.search(r"\[cat:\s*([^\]]+)\]", riga)
        if match_cat:
            flusso["categoria"] = match_cat.group(1)

        # Risk info
        match_risk = re.search(r"\[Risk:\s*([^\]]+)\]", riga)
        if match_risk:
            flusso["risk"] = match_risk.group(1)

        match_risk_score = re.search(r"\[Risk Score:\s*([^\]]+)\]", riga)
        if match_risk_score:
            flusso["risk_score"] = match_risk_score.group(1)

        match_risk_info = re.search(r"\[Risk Info:\s*([^\]]+)\]", riga)
        if match_risk_info:
            flusso["risk_info"] = match_risk_info.group(1)

        flussi.append(flusso)
        counter += 1

# --- AGGREGAZIONE ---
#aggregati = {}
#for flusso in flussi:
#    chiave = (
#        flusso.get("ip_sorgente"),
#        flusso.get("ip_destinazione"),
#        flusso.get("porta_destinazione"),
#        flusso.get("protocollo"),
#    )
#    if chiave not in aggregati:
#        flusso["numero_flussi_simili"] = 1
#        aggregati[chiave] = flusso
#    else:
#        aggregati[chiave]["numero_flussi_simili"] += 1
#flussi_finali = list(aggregati.values())

with open(output_file, 'w') as f_out:
    json.dump(flussi, f_out, indent=4)

# --- RIEPILOGO PROTOCOLLI ---
protocol_counts = Counter()

for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()
    if "dns" in proto:
        protocol_counts["DNS"] += 1
    elif "http" in proto:
        protocol_counts["HTTP"] += 1
    elif "tls" in proto:
        protocol_counts["TLS"] += 1
    elif "unknown" in proto:
        protocol_counts["Unknown"] += 1

# Stampa riepilogo
riepilogo = ", ".join([f"{v} flussi {k}" for k, v in protocol_counts.items()])
print(f"\nRilevati: {riepilogo}")

# --- STAMPA FLUSSI DNS ---
print("\nFlussi DNS rilevati (SNI & IP):\n")
for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()
    if "dns" in proto:
        sni = flusso.get("sni", "N/A")
        ip = flusso.get("dns_ip", "N/A")
        print(f"SNI: {sni} - IP: {ip}")


# --- STAMPA FLUSSI HTTP ---
print("\nFlussi HTTP rilevati:\n")
for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()
    if "http" in proto:
        ip_sorgente = flusso.get("ip_sorgente", "N/A")
        porta_sorgente = flusso.get("porta_sorgente", "N/A")
        ip_destinazione = flusso.get("ip_destinazione", "N/A")
        porta_destinazione = flusso.get("porta_destinazione", "N/A")
        url = flusso.get("url", "N/A")
        sni = flusso.get("sni", "N/A")
        pkts_sorgente = flusso.get("pkts_sorgente", 0)
        pkts_destinazione = flusso.get("pkts_destinazione", 0)

        print(f"{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione} | "
              f"URL: {url} | SNI: {sni} | Pacchetti: {pkts_sorgente} -> {pkts_destinazione}")


# --- STAMPA FLUSSI TLS ---
print("\nFlussi TLS rilevati:\n")
for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()
    if "tls" in proto:
        ip_sorgente = flusso.get("ip_sorgente", "N/A")
        porta_sorgente = flusso.get("porta_sorgente", "N/A")
        ip_destinazione = flusso.get("ip_destinazione", "N/A")
        porta_destinazione = flusso.get("porta_destinazione", "N/A")
        ja3s = flusso.get("ja3s", "N/A")
        ja4 = flusso.get("ja4", "N/A")
        sni = flusso.get("sni", "N/A")
        pkts_sorgente = flusso.get("pkts_sorgente", 0)
        pkts_destinazione = flusso.get("pkts_destinazione", 0)

        print(f"{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione} | "
              f"JA3S: {ja3s}, JA4: {ja4}, SNI: {sni}, "
              f"Pacchetti: {pkts_sorgente} -> {pkts_destinazione}")

# --- STAMPA FLUSSI UNKNOW ---
print("\nFlussi Unknown rilevati:\n")
for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()
    if "unknown" in proto:
        ip_sorgente = flusso.get("ip_sorgente", "N/A")
        porta_sorgente = flusso.get("porta_sorgente", "N/A")
        ip_destinazione = flusso.get("ip_destinazione", "N/A")
        porta_destinazione = flusso.get("porta_destinazione", "N/A")
        pkts_sorgente = flusso.get("pkts_sorgente", 0)
        pkts_destinazione = flusso.get("pkts_destinazione", 0)

        print(f"{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione} | "
              f"Pacchetti: {pkts_sorgente} -> {pkts_destinazione}")



