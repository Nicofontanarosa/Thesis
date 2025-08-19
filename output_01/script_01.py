
import re
import json
import argparse

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
        if not riga or not re.search(r"\d+\.\d+\.\d+\.\d+:\d+", riga):
            continue

        flusso = {"id": counter, "riga_grezza": riga}

        # Protocollo
        match_proto = re.search(r"\[proto:\s*([\d\.]+\/[^\]]+)\]", riga)
        if match_proto:
            flusso["protocollo"] = match_proto.group(1)

        # Categoria
        match_cat = re.search(r"\[cat:\s*([^\]]+)\]", riga)
        if match_cat:
            flusso["categoria"] = match_cat.group(1)

        # IP e porte
        match_ip = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)", riga)
        if match_ip:
            flusso["ip_sorgente"] = match_ip.group(1)
            flusso["porta_sorgente"] = match_ip.group(2)
            flusso["ip_destinazione"] = match_ip.group(3)
            flusso["porta_destinazione"] = match_ip.group(4)

        # SNI / Hostname
        match_sni = re.search(r"\[Hostname/SNI:\s*([^\]]+)\]", riga)
        if match_sni:
            flusso["sni"] = match_sni.group(1)

        # URL
        match_url = re.search(r"\[URL:\s*([^\]]+)\]", riga)
        if match_url:
            flusso["url"] = match_url.group(1)

        # ALPN
        match_alpn = re.search(r"\[\(Advertised\) ALPNs:\s*([^\]]+)\]", riga)
        if match_alpn:
            flusso["alpn"] = match_alpn.group(1)

        # TLS Versions
        match_tls = re.search(r"\[TLS Supported Versions:\s*([^\]]+)\]", riga)
        if match_tls:
            flusso["tls_versions"] = match_tls.group(1)

        # Fingerprint TCP
        match_tcp_fp = re.search(r"\[TCP Fingerprint:\s*([^\]]+)\]", riga)
        if match_tcp_fp:
            flusso["tcp_fingerprint"] = match_tcp_fp.group(1)

        # JA3/JA4
        match_ja3 = re.search(r"\[JA3S:\s*([^\]]+)\]", riga)
        if match_ja3:
            flusso["ja3s"] = match_ja3.group(1)

        match_ja4 = re.search(r"\[JA4:\s*([^\]]+)\]", riga)
        if match_ja4:
            flusso["ja4"] = match_ja4.group(1)

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

        flussi.append(flusso)
        counter += 1

with open(output_file, 'w') as f_out:
    json.dump(flussi, f_out, indent=4)

print(f"[OK] Estratti {len(flusso)} flussi in {output_file}")
