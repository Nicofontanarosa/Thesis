
import re
import json
import argparse
from collections import Counter
import os
import config
from collections import defaultdict

# parsing args
args = config.get_args()
input_file = args.input_file
output_file = args.output

# stampa dei file usati
config.print_files(input_file, output_file)

# lista dei protocolli da mantenere
protocols = config.PROTOCOLS

flussi = []
counter = 1
ip_host = []

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
            ip_host.append(match_ip_only.group(1))
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
        
        # se mettessi degli if per protocollo, i campi TLS o HTTP per i flussi sconosciuti non verrebbero visualizzati
        #    if "DNS" in match_proto.group(1):
        # DNS IP
        match_dns_ip = re.search(r"\]\[([\d]+\.[\d]+\.[\d]+\.[\d]+)\]", riga)
        if match_dns_ip:
            flusso["dns_ip"] = match_dns_ip.group(1)

        # DNS ID
        match_dns_id = re.search(r"\[DNS Id:\s*([^\]]+)\]", riga)
        if match_dns_id:
            flusso["dns_id"] = match_dns_id.group(1)

        #    if "HTTP" in match_proto.group(1):
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

        #    if "TLS" in match_proto.group(1):
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

        # ECH Encrypted Client Hello
        match_cipher = re.search(r"\[ECH:\s*([^\]]+)\]", riga)
        if match_cipher:
            flusso["ech"] = match_cipher.group(1)

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

        # Numero pacchetti sorgente e destinazione TEMP
        match_pkts = re.search(r"\[(\d+)\s+pkts/[^<]+<->\s+(\d+)\s+pkts/", riga)
        if match_pkts:
            flusso["pkts_sorgente"] = int(match_pkts.group(1))
            flusso["pkts_destinazione"] = int(match_pkts.group(2))

        # Fingerprint TCP
        match_tcp_fp = re.search(r"\[TCP Fingerprint:\s*([^\]]+)\]", riga)
        if match_tcp_fp:
            flusso["tcp_fingerprint"] = match_tcp_fp.group(1)

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

# --- RIEPILOGO PROTOCOLLI ---
protocol_counts = Counter()

for flusso in flussi:
    proto = flusso.get("proto_field", "").lower()

    # cerca se uno dei protocolli definiti è contenuto nella stringa proto
    matched = False
    for p in protocols:
        if p.lower() in proto:
            protocol_counts[p] += 1
            matched = True
            break

    # se nessun protocollo è stato riconosciuto → conta come "Unknown"
    # 1 sarà sempre l'indirizzo ip host sorgente
    if not matched:
        protocol_counts["Unknown"] += 1

# --- AGGREGAZIONE FLUSSI TLS ---
aggregati = {}
flussi_finali = []

for flusso in flussi:

    pacchetti = f"{flusso.get('pkts_sorgente', 'N/A')} <-> {flusso.get('pkts_destinazione', 'N/A')}"
    # rimuovo i vecchi campi
    flusso.pop("pkts_sorgente", None)
    flusso.pop("pkts_destinazione", None)

    # se è TLS aggrega
    #if flusso.get("proto_field") and "TLS" in flusso.get("proto_field"):
    # aggiungo tutti i campi disponibili per aggregare i flussi
    chiave = tuple(flusso.get(key) for key in config.KEY)

    if chiave not in aggregati:
        flusso["numero_flussi_simili"] = 1
        flusso["pacchetti_scambiati"] = [pacchetti]
        aggregati[chiave] = flusso
    else:
        aggregati[chiave]["numero_flussi_simili"] += 1
        aggregati[chiave]["pacchetti_scambiati"].append(pacchetti)
    
flussi_finali = list(aggregati.values())

with open(output_file, 'w') as f_out:
    json.dump(flussi_finali, f_out, indent=4)

def stampa_flussi(flussi_finali):

    # Clear del terminale all'apertura
    config.clear_terminal()

    # Stampa riepilogo
    riepilogo = ", ".join([f"{v} flussi {k}" for k, v in protocol_counts.items()])
    print(f"\nRilevati: {riepilogo}")

    # --- STAMPA FLUSSI DNS ---
    print("\nFlussi DNS rilevati (SNI, Plain Text & IP):\n")
    for flusso in flussi_finali:
        proto = flusso.get("proto_field", "").lower()
        if "dns" in proto:
            sni = flusso.get("sni", "N/A")
            plain = flusso.get("plain_text", "N/A")
            ip = flusso.get("dns_ip", "N/A")
            print(f"SNI: {sni:40} | Plain Text: {plain:25} | IP: {ip}")

    # --- STAMPA FLUSSI HTTP ---
    print("\nFlussi HTTP rilevati:\n")
    for flusso in flussi_finali:
        proto = flusso.get("proto_field", "").lower()
        if "http" in proto:
            ip_sorgente = flusso.get("ip_sorgente", "N/A")
            porta_sorgente = flusso.get("porta_sorgente", "N/A")
            ip_destinazione = flusso.get("ip_destinazione", "N/A")
            porta_destinazione = flusso.get("porta_destinazione", "N/A")
            url = flusso.get("url", "N/A")
            sni = flusso.get("sni", "N/A")
            plain = flusso.get("plain_text", "N/A")
            pacchetti_scambiati = flusso.get("pacchetti_scambiati", "N/A")
            ip_field = flusso.get("ip_field", "N/A")

            print(f"{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione} | "
                f"URL: {url:40} | IP: {ip_field:25} | SNI: {sni:40} | Plain Text: {plain:25} | Pacchetti_scambiati: {pacchetti_scambiati}")

    # --- STAMPA FLUSSI TLS ---
    print("\nFlussi TLS rilevati:\n")
    for flusso in flussi_finali:
        proto = flusso.get("proto_field", "").lower()
        if "tls" in proto:
            ip_sorgente = flusso.get("ip_sorgente", "N/A")
            porta_sorgente = flusso.get("porta_sorgente", "N/A")
            ip_destinazione = flusso.get("ip_destinazione", "N/A")
            porta_destinazione = flusso.get("porta_destinazione", "N/A")
            ja3s = flusso.get("ja3s", "N/A")
            ja4 = flusso.get("ja4", "N/A")
            sni = flusso.get("sni", "N/A")
            ech = flusso.get("ech", "N/A")
            pacchetti_scambiati = flusso.get("pacchetti_scambiati", "N/A")
            numero_flussi_simili = flusso.get("numero_flussi_simili", "N/A")
            ip_field = flusso.get("ip_field", "N/A")

            print(f"""{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione}
    │
    ├── JA3S: {ja3s}
    ├── JA4: {ja4}
    ├── SNI: {sni}
    ├── ECH: {ech}
    ├── IP: {ip_field}
    ├── Numero flussi simili: {numero_flussi_simili}
    └── Pacchetti scambiati: {pacchetti_scambiati}
                """)

    # --- STAMPA FLUSSI UNKNOW ---
    print("\nFlussi Unknown rilevati:\n")
    for flusso in flussi_finali:
        proto = flusso.get("proto_field", "").lower()
        if "unknown" in proto:
            ip_sorgente = flusso.get("ip_sorgente", "N/A")
            porta_sorgente = flusso.get("porta_sorgente", "N/A")
            ip_destinazione = flusso.get("ip_destinazione", "N/A")
            porta_destinazione = flusso.get("porta_destinazione", "N/A")
            pkts_sorgente = flusso.get("pkts_sorgente", 0)
            pkts_destinazione = flusso.get("pkts_destinazione", 0)
            ja3s = flusso.get("ja3s", "N/A")
            ja4 = flusso.get("ja4", "N/A")
            sni = flusso.get("sni", "N/A")
            ech = flusso.get("ech", "N/A")
            url = flusso.get("url", "N/A")
            ip_field = flusso.get("ip_field", "N/A")

            print(f"""{ip_sorgente}:{porta_sorgente} -> {ip_destinazione}:{porta_destinazione}
    │
    ├── JA3S: {ja3s}
    ├── JA4: {ja4}
    ├── SNI: {sni}
    ├── ECH: {ech}
    ├── URL: {url}
    ├── IP: {ip_field}
    ├── Numero flussi simili: {numero_flussi_simili}
    └── Pacchetti scambiati: {pacchetti_scambiati}
                """)

    raggruppa_per_hostname(flussi_finali)

def raggruppa_per_hostname(flussi):
    gruppi = defaultdict(list)

    for flusso in flussi:
        if flusso.get("proto_field", "").upper() == "5/DNS" or flusso.get("ip_destinazione") in ip_host:
            continue
        hostname = flusso.get("sni") or "SNI_non_disponibile"
        ip_dest = flusso.get("ip_destinazione")
        if ip_dest:
            porta_dest = flusso.get("porta_destinazione")
            gruppi[hostname].append(f"{ip_dest}:{porta_dest}")
        else: continue

    # stampa i gruppi
    for hostname, indirizzi in gruppi.items():
        print(f"\nHostname/SNI: {hostname}")
        print("Indirizzi associati:")
        for addr in set(indirizzi):  # uso set per evitare duplicati
            print(f"  - {addr}")

def ricerca_correlata(flussi, parola):
    # flussi è la lista di dizionari
    risultati = []
    visitati = set()

    # coda di ricerca (BFS)
    da_visitare = []

    # fase 1: trova i flussi che contengono la parola
    for i, flusso in enumerate(flussi):
        if flusso.get("proto_field", "").upper() == "5/DNS":
            continue
        for v in flusso.values():
            if parola.lower() in str(v).lower():
                da_visitare.append(i)

    # fase 2: BFS sugli attributi correlati
    while da_visitare:
        idx = da_visitare.pop(0)
        if idx in visitati:
            continue
        visitati.add(idx)
        flusso = flussi[idx]
        if flusso.get("proto_field", "").upper() == "5/DNS":
            continue  # scarta DNS
        risultati.append(flusso)

        correlati = [flusso.get(key) for key in config.CLUSTER_KEYS]

        # cerca altri flussi che matchano questi valori
        for j, altro in enumerate(flussi):
            if j in visitati:
                continue
            for key in correlati:
                if key and key != "N/A" and key in altro.values():
                    da_visitare.append(j)

    return risultati

def ricerca_flussi(flussi_finali):
    while True:

        stampa_flussi(flussi_finali)

        parola = input("\nRicerca: ").strip()
        if not parola:
            continue
        else:
            cluster = ricerca_correlata(flussi_finali, parola)
            #flussi_da_mostrare = [
            #    f for f in flussi_finali
            #    if any(parola.lower() in str(v).lower() for v in f.values())
            #]

        stampa_flussi(cluster)

        scelta = input("\nPremi INVIO per continuare o digita 'esci' per uscire: ").strip().lower()
        if scelta == "esci":
            break

ricerca_flussi(flussi_finali)
