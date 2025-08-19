import re
import json

input_file = "Traffico_in_Chiaro_Vint-Sub-Traid_output_filtrato.json"

dns_flussi = []
altri_flussi = []
counter = 1

with open(input_file, 'r') as f_in:
    for riga in f_in:
        riga = riga.strip()
        if not riga:
            continue

        # Estrai protocollo (es. DNS, HTTPS, ecc.)
        match_proto = re.search(r"\[proto:\s*\d+\/([^\]]+)\]", riga)
        protocollo = match_proto.group(1) if match_proto else "Sconosciuto"

        # Estrai IP sorgente e destinazione
        match_ip = re.search(r"\w\s+(\d+\.\d+\.\d+\.\d+):\d+\s+<->\s+(\d+\.\d+\.\d+\.\d+):\d+", riga)
        if match_ip:
            ip_sorgente = match_ip.group(1)
            ip_destinazione = match_ip.group(2)

            # Estrai SNI o Hostname
            match_sni = re.search(r"\[Hostname/SNI:\s*([^\]]+)\]", riga)
            sni = match_sni.group(1) if match_sni else None

            flusso = {
                "id": counter,
                "ip_sorgente": ip_sorgente,
                "ip_destinazione": ip_destinazione,
                "protocollo": protocollo,
                "sni": sni
            }

            if protocollo.upper() == "DNS":
                dns_flussi.append(flusso)
            else:
                altri_flussi.append(flusso)

            counter += 1

# DNS prima, altri dopo
result = dns_flussi + altri_flussi

with open("Traffico_in_Chiaro_Vint-Sub-Traid_output_script.json", 'w') as f_out:
    json.dump(result, f_out, indent=4)
