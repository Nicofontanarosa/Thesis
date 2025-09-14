
#################################################################
# File: flow_processor.py to process filtered nDPI JSON and save final output
#################################################################

import re
import json
# my file
import config
import constants
# -------------------------------------------

log_file_removed_flows_maxsni = "tmp/removed_flows_maxsni.txt"
config.clear_log(log_file_removed_flows_maxsni)

# -------------------------------------------

def remove_flows_maxsin(final_flows):

    # filtering SNIs with more than 4 domains
    filtered_flows = []
    for flow in final_flows:
        sni = flow.get("sni", "")
        if not sni or len(sni.split(".")) <= constants.SNI_MAX_DOMAIN:
            filtered_flows.append(flow)
        else:
            config.log_message(f"[REMOVED] SNI with more than 4 domains: {sni}", log_file_removed_flows_maxsni)

    return  filtered_flows

# -------------------------------------------

def flow_processor(input_file, output_file):
    
    # flows read
    flows = []
    #ip_host = []
    # flows aggregation
    aggregated = {}
    # flows to print
    final_flows = []

    # 1° file open
    with open(input_file, 'r') as f_in:
        for line in f_in:
            line = line.strip()
            # skip empty lines or lines without IP ( further but not necessary check )
            if not line or not re.search(r"\d+\.\d+\.\d+\.\d+", line):
                continue

            flow = {}

            # Host
            #match_ip_only = re.match(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s*$", line)
            #if match_ip_only:
            #    flow["ip_host"] = match_ip_only.group(1)
            #    flows.append(flow)
            #    ip_host.append(match_ip_only.group(1))
            #    continue

            # IP
            match_ip_field = re.search(r"\[IP:\s*([^\]]+)\]", line)
            if match_ip_field:
                flow["ip_field"] = match_ip_field.group(1)

            # Transport Protocol
            match_transport = re.search(r"^\s*\d+\s+([A-Za-z0-9]+)", line)
            if match_transport:
                flow["transport_protocol"] = match_transport.group(1)

            # Protocol
            match_proto = re.search(r"\[proto:\s*([\d\.]+\/[^\]]+)\]", line)
            if match_proto:
                flow["proto_field"] = match_proto.group(1)
            
            # DNS IP
            match_dns_ip = re.search(r"\]\[([\d]+\.[\d]+\.[\d]+\.[\d]+)\]", line)
            if match_dns_ip:
                flow["dns_ip"] = match_dns_ip.group(1)

            # DNS ID
            match_dns_id = re.search(r"\[DNS Id:\s*([^\]]+)\]", line)
            if match_dns_id:
                flow["dns_id"] = match_dns_id.group(1)

            # URL
            match_url = re.search(r"\[URL:\s*([^\]]+)\]", line)
            if match_url:
                flow["url"] = match_url.group(1)

            # User-Agent
            match_ua = re.search(r"\[User-Agent:\s*([^\]]+)\]", line)
            if match_ua:
                flow["user_agent"] = match_ua.group(1)

            # TLS Version used
            match_tls_version = re.search(r"\[(TLSv[0-9.]+)\]", line)
            if match_tls_version:
                flow["tls_version"] = match_tls_version.group(1)

            # JA3/JA4
            match_ja3 = re.search(r"\[JA3S:\s*([^\]]+)\]", line)
            if match_ja3:
                flow["ja3s"] = match_ja3.group(1)

            match_ja4 = re.search(r"\[JA4:\s*([^\]]+)\]", line)
            if match_ja4:
                flow["ja4"] = match_ja4.group(1)

            # TLS certificate details
            match_servernames = re.search(r"\[ServerNames:\s*([^\]]+)\]", line)
            if match_servernames:
                flow["servernames"] = match_servernames.group(1)

            match_issuer = re.search(r"\[Issuer:\s*([^\]]+)\]", line)
            if match_issuer:
                flow["issuer"] = match_issuer.group(1)

            match_subject = re.search(r"\[Subject:\s*([^\]]+)\]", line)
            if match_subject:
                flow["subject"] = match_subject.group(1)

            match_certificate = re.search(r"\[Certificate\s*([^\]]+)\]", line)
            if match_certificate:
                flow["certificate"] = match_certificate.group(1)

            match_validity = re.search(r"\[Validity:\s*([^\]]+)\]", line)
            if match_validity:
                flow["validity"] = match_validity.group(1)

            # QUIC Version
            match_quic = re.search(r"\[QUIC ver:\s*([^\]]+)\]", line)
            if match_quic:
                flow["quic_version"] = match_quic.group(1)

            # Plain Text
            match_plain = re.search(r"\[PLAIN TEXT\s*\(([^)]+)\)\]", line)
            if match_plain:
                flow["plain_text"] = match_plain.group(1)

            # SNI / Hostname
            match_sni = re.search(r"\[Hostname/SNI:\s*([^\]]+)\]", line)
            if match_sni:
                flow["sni"] = match_sni.group(1)
        
            # IP and Ports
            match_ip = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            if match_ip:
                flow["ip_source"] = match_ip.group(1)
                flow["port_source"] = match_ip.group(2)
                flow["ip_destination"] = match_ip.group(3)
                flow["port_destination"] = match_ip.group(4)

            # pkts source and destination count
            match_pkts = re.search(r"\[(\d+)\s+pkts/[^<]+(?:<->|->|<-)\s+(\d+)\s+pkts/", line)
            if match_pkts:
                flow["pkts_source"] = int(match_pkts.group(1))
                flow["pkts_destination"] = int(match_pkts.group(2))

            # Fingerprint TCP
            match_tcp_fp = re.search(r"\[TCP Fingerprint:\s*([^\]]+)\]", line)
            if match_tcp_fp:
                flow["tcp_fingerprint"] = match_tcp_fp.group(1)

            # Risk info
            match_risk = re.search(r"\[Risk:\s*([^\]]+)\]", line)
            if match_risk:
                flow["risk"] = match_risk.group(1)

            match_risk_score = re.search(r"\[Risk Score:\s*([^\]]+)\]", line)
            if match_risk_score:
                flow["risk_score"] = match_risk_score.group(1)

            match_risk_info = re.search(r"\[Risk Info:\s*([^\]]+)\]", line)
            if match_risk_info:
                flow["risk_info"] = match_risk_info.group(1)

            flows.append(flow)

    for flow in flows:

        packets = f"{flow.get('pkts_source', 'N/A')} <-> {flow.get('pkts_destination', 'N/A')}"
        # remove pkts count from flow
        flow.pop("pkts_source", None)
        flow.pop("pkts_destination", None)

        proto = flow.get("proto_field", "").lower()

        # create key for aggregation
        if "tls" in proto:
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["TLS"])
        elif "http" in proto:
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["HTTP"])
        elif "dns" in proto:
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["DNS"])
        elif "quic" in proto:    
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["QUIC"])
        elif "smtp" in proto:
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["SMTP"])
        else:
            key = tuple(flow.get(k) for k in constants.KEYS_BY_PROTOCOL["Unknown"])

        if key not in aggregated:
            flow["similar_flows_count"] = 1
            flow["exchanged_packets"] = [packets]
            aggregated[key] = flow
        else:
            aggregated[key]["similar_flows_count"] += 1
            aggregated[key]["exchanged_packets"].append(packets)

    final_flows = list(aggregated.values())

    final_flows = remove_flows_maxsin(final_flows)

    with open(output_file, 'w') as f_out:
        json.dump(final_flows, f_out, indent=4)

    return final_flows

#################################################################
# End of flow_processor.py
#################################################################