
#################################################################
# File: filter.py to filter nDPI output
# Keeps only relevant flows based on protocol and content
#################################################################

import re
# my file
import config
import constants
# -------------------------------------------

# protocols to keep
protocols = constants.PROTOCOLS

# At the beginning of run_pipeline or right after the imports
log_file_stats = "tmp/stats.txt"
log_file_flows = "tmp/flows.txt"
config.clear_log(log_file_stats)
config.clear_log(log_file_flows)

def flow_filter(input_file, output_file):
    
    # flow to keep and remove
    keep_flows = []
    removed_flows = []
    empty_flows = []
    ipv6_flows = []
    incomplete_tls_flows = []
    no_sni_flows = []
    # all protocols present in the file
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
            
    # printing protocols and IPs read/analyzed

    config.log_message(">> Lists of protocols read:\n\n", log_file_stats)
    for proto in sorted(all_protocols_in_file):
        config.log_message(f"   + {proto}\n", log_file_stats)

    config.log_message("\n>> Lists of protocols supported:\n\n", log_file_stats)
    for proto in sorted(protocols):
        config.log_message(f"   + {proto}\n", log_file_stats)

    #config.log_message("\n>> List of IPs read:\n\n", log_file_stats)
    #for ip in sorted(all_ip_in_file):
    #    config.log_message(f"   + {ip}", log_file_stats)

    not_analyzed = all_protocols_in_file - protocols
    if not_analyzed:
        config.log_message("\n[red]>> WARNING PROTOCOLS NOT ANALYZED[/red]\n\n", log_file_stats)
        for proto in sorted(not_analyzed):
            config.log_message(f"   [red]+ {proto}[/red]\n", log_file_stats)
        
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
    #host_ip_only_pattern = re.compile(r"^\s*\d+\s+([0-9a-fA-F:.]+)\s+")
    # regex to match lines with IPv6 addresses
    ipv6_pattern = re.compile(r"\[[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\]")
    # regex to match lines with plen bins all zero
    plen_bins_empty_pattern = re.compile(r"\[Plen Bins: (0,){47}0\]")
    # regex to match incomplete TLS flows (no handshake)
    tls_incomplete_pattern = re.compile(r"^\s*\d+\s+(?:TCP|UDP)\s+\d+\.\d+\.\d+\.\d+:\d+\s+(?:<->|->|<-)\s+\d+\.\d+\.\d+\.\d+:\d+\s+\[proto:\s*\d+/(?:TLS|QUIC)\]\[IP:\s*[^\]]+\]\[(\d+)\s+pkts\s*[^\]]+\]")
    # regex to match lines without SNI/Hostname
    sni_pattern = re.compile(r"\[Hostname/SNI:\s*[^\]]+\]")

    # 1° version of the filtering script using regex
    #sed -E 's/\[Goodput ratio: [^]]+\]\[[^]]+\]//g; s/\[bytes ratio: [^]]+\]//g; s/\[(Encrypted|ClearText)\]//g; s/\[Confidence: [^]]+\]//g;
    #s/\[FPC: [^]]+\]//g; s/\[DPI packets: [^]]+\]//g; s/\[IAT [^]]+\]//g; s/\[Pkt Len [^]]+\]//g'; s/\[DNS Id: [^]]+\]//g'
    #s/\[Plen Bins: [^]]+\]//g; s/\[PLAIN TEXT \([^]]+\)\]//g;

    # regex to remove the fields [Goodput ratio: ...][...]                  [Goodput ratio: 66/83][4.53 sec]
    goodput_pattern = re.compile(r"\[Goodput ratio: [^\]]+\]\[[^\]]*\]")
    # regex to remove the fields [bytes ratio: ...]                         [bytes ratio: 181934/365756]
    bytes_pattern = re.compile(r"\[bytes ratio: [^\]]+\]")
    # regex to remove the fields [Encrypted] or [ClearText]                 [Encrypted]
    text_pattern = re.compile(r"\[(Encrypted|ClearText)\]")
    # regex to remove the fields [Safari] or [Chrome]                       [Safari]
    host_pattern = re.compile(r"\[(Safari|Chrome|Firefox)\]")
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

    # regex to remove the fields [Cipher: ...]                              [Cipher: TLS_AES_256_GCM_SHA384]
    cipher_pattern = re.compile(r"\[Cipher: [^]]+\]")
    # regex to remove the fields [ECH: ...]                                 [ECH: Encrypted Client Hello]
    ech_pattern = re.compile(r"\[ECH: [^]]+\]")
    # regex to remove the fields [(Negotiated) ALPN: ...]                   [(Negotiated) ALPNs: h2,http/1.1]
    alpn_pattern = re.compile(r"\[\((Negotiated|Advertised)\) (ALPNs|ALPN): [^]]+\]")
    # regex to remove the fields [TLS Supported Versions: ...]              [TLS Supported Versions: TLSv1.3,TLSv1.2]
    tls_versions_pattern = re.compile(r"\[TLS Supported Versions: [^]]+\]")

    # -------------------------------------------

    # regex to remove the fields [StatusCode: ....]                         [StatusCode: 200]
    status_pattern = re.compile(r"\[StatusCode:\s*([^\]]+)\]")
    # regex to remove the fields [Content-Type: ....]                       [Content-Type: text/plain]
    ct_pattern = re.compile(r"\[Content-Type:\s*([^\]]+)\]")

    # -------------------------------------------

    # 2° - 3° file open
    with open(input_file, 'r') as fin, open(output_file, 'w') as fout:

        for line in fin:
            line_stripped = line.strip()
            
            # check for lines with only the host IP
            #if host_ip_only_pattern.match(line_stripped):
            #    keep_flows.append(line)
            #    fout.write(line)
            #    continue
            
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
                clean_line = cipher_pattern.sub("", clean_line)
                clean_line = ech_pattern.sub("", clean_line)
                clean_line = alpn_pattern.sub("", clean_line)
                clean_line = tls_versions_pattern.sub("", clean_line)
                clean_line = status_pattern.sub("", clean_line)
                clean_line = ct_pattern.sub("", clean_line)

                # check for incomplete TLS flows
                if tls_incomplete_pattern.fullmatch(clean_line.strip()):
                    incomplete_tls_flows.append(line)
                    continue

                # check for flows without SNI/Hostname
                if not sni_pattern.search(clean_line):
                    no_sni_flows.append(line)
                    continue

                # add good flows
                keep_flows.append(line)
                fout.write(clean_line)

            elif pattern_general.search(line_stripped):
                # remove flows matching general protocol pattern
                removed_flows.append(line)

    # Print summary
    config.log_message(f"\n- Flows read: {len(keep_flows) + len(removed_flows) + len(empty_flows) + len(ipv6_flows) + len(incomplete_tls_flows) + len(no_sni_flows)}", log_file_flows)
    config.log_message(f"- Flows kept: {len(keep_flows)}", log_file_flows)
    config.log_message(f"- Flows removed: {len(removed_flows) + len(empty_flows) + len(ipv6_flows) + len(incomplete_tls_flows) + len(no_sni_flows)}", log_file_flows)
    config.log_message(f"----- General flows removed: {len(removed_flows)}", log_file_flows)
    config.log_message(f"----- Empty flows removed: {len(empty_flows)}", log_file_flows)
    config.log_message(f"------ IPv6 flows removed: {len(ipv6_flows)}", log_file_flows)
    config.log_message(f"------ Incomplete TLS flows removed: {len(incomplete_tls_flows)}", log_file_flows)
    config.log_message(f"------ No SNI flows removed: {len(no_sni_flows)}", log_file_flows)

    # ---------------------------------------------------
    # Print removed flows ( with categories )
    # ---------------------------------------------------
    if removed_flows:
        print("\n> --- General flows removed ---")
        for f in removed_flows:
            print(f.strip())

    if empty_flows:
        print("\n> --- Empty flows removed ---")
        for f in empty_flows:
            print(f.strip())

    if ipv6_flows:
        print("\n--- IPv6 flows removed ---")
        for f in ipv6_flows:
            print(f.strip())

    if incomplete_tls_flows:
        print("\n--- Incomplete TLS flows removed ---")
        for f in incomplete_tls_flows:
            print(f.strip())

    if no_sni_flows:
        print("\n--- No SNI flows removed ---")
        for f in no_sni_flows:
            print(f.strip())
            
#################################################################
# End of filter.py
#################################################################