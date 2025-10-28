
#################################################################
# File: get_info.py
#################################################################

import requests
import whois as whois
import json
import os
# my file
import constants
import config

# -------------------------------------------

log_file_rules = "tmp/rules.txt"
config.clear_log(log_file_rules)

# -------------------------------------------

def classify_domain_AI(domain):

    # set up the base URL for the local Ollama API
    url = "http://localhost:11434/api/chat"

    # define the model and the input prompt
    prompt = f"You are a traffic monitoring assistant. Tell me in a COUPLE OF WORD the name of the service / application to which this domain belongs: {domain}"

    # define the payload
    payload = {
        "model": "gemma3",  # replace with the model name you're using
        "messages": [{"role": "user", "content": prompt}]
    }

    # send the HTTP POST request with streaming enabled
    response = requests.post(url, json=payload)
    message = ""
    # check the response status
    if response.status_code == 200:
        for line in response.iter_lines(decode_unicode=True):
            if line:  # Ignore empty lines
                try:
                    json_data = json.loads(line)
                    if "message" in json_data and "content" in json_data["message"]:
                        content = json_data["message"]["content"]
                        # Mantieni solo lettere, numeri e spazi
                        filtered = "".join(c for c in content if c.isalnum() or c.isspace())
                        message += filtered + ""
                except json.JSONDecodeError:
                    print(f"\nFailed to parse line: {line}")

    return message

# -------------------------------------------

def classify_domains(clusters, output_file, protoname):

    output_folder = os.path.dirname(output_file)
    # make the complete path for the rules file
    rules_file = os.path.join(output_folder, "rules.txt")
    config.clear_log(rules_file)

    if not clusters:
        rule = "unknown@UnknownProto"
        instructions = "\n[red]>> NOT ENOUGH INFORMATION TO GENERATE A RULE[/red]"
        with open(rules_file, "a") as f:
            f.write(f"{rule}\n{instructions}\n{'-'*62}\n")
        config.log_message(f"{rule}\n{instructions}\n{'-'*62}\n", log_file_rules)

    for cluster in clusters:

        snis = cluster.get('sni_list', [])
        ja4 = cluster.get('ja4', "")
        raw_cert = cluster.get('certificate', [])
        certificate = {item[0]: item[1] for item in raw_cert if len(item) == 2}

        print(f"\n\n{certificate}\n\n")

        # === Rule and instructions ===
        instructions = ""
        rule = ""
        
        if constants.SHOW_NAME_HINT:

            for d in snis:
                try:
                    w = whois.whois(d)
                    protoname = w.get('registrant_organization') or w.get('admin_organization') or w.get('org')
                    #print(f"\n---{org.lower()}---{ 'true' if org.lower() in constants.REDACTED_ORGS else 'false'}----")

                    if protoname is None or protoname.lower() in constants.REDACTED_ORGS:
                        protoname = classify_domain_AI(d)
                    else:
                        protoname = classify_domain_AI(d)

                except Exception as e:
                    protoname = classify_domain_AI(d)

        # === Prefer SNI if available ===
        if snis:
            host_entries = ",".join([f'host:"{sni}"' for sni in sorted(snis)])
            rule = f"{host_entries}@{protoname}"
            instructions = (
                "\n>> To add this rule based on SNI:\n"
                "   [+] Open the file: `nDPI/example/protos.txt`\n"
                f"   [+] Paste the following rule: {rule}\n"
            )

        # === If no SNI, use certificate ===
        elif certificate.get('subject') and "CN=" in certificate.get('subject'):

            subject = certificate.get('subject')

            # extracts the CN from the subject field
            def extract_cn(field):
                if not field or field.lower() == "none":
                    return None
                for part in field.split(","):
                    part = part.strip()
                    if part.startswith("CN="):
                        return part.replace("CN=", "").strip()
                return None

            subject_cn = extract_cn(subject)

            if subject_cn and subject.lower():
                rule = f'trusted_issuer_dn:"{subject}"@"{protoname}"'

            instructions = (
                "\n>> To add this rule based on CERTIFICATE:\n"
                "   [+] Open `nDPI/src/include/ndpi_protocol_ids.h`\n"
                "      >> Add at the end of the typedef enum:\n"
                f"         [+] NDPI_PROTOCOL_{protoname.upper()} = 453,\n"
                "         [+] Replace 453 with an available protocol number.\n"
                "   [+] Open `nDPI/src/lib/ndpi_main.c`\n"
                "      >> Inside `static void init_protocol_defaults`, add:\n"
                f"         [+] ndpi_set_proto_defaults(ndpi_str, 0, 1, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_{protoname.upper()}, {protoname}, NDPI_PROTOCOL_CATEGORY_NETWORK, NDPI_PROTOCOL_QOE_CATEGORY_UNSPECIFIED, ndpi_build_default_ports(ports_a, 0,0,0,0,0), ndpi_build_default_ports(ports_b, 0,0,0,0,0), 0);\n"
                "   [+] Open `nDPI/src/lib/ndpi_content_match.c.inc`\n"
                "      >> In `static ndpi_tls_cert_name_match tls_certificate_match[]`, add:\n"
                f"         [+] {{ \"{subject}\", NDPI_PROTOCOL_{protoname.upper()} }},\n\n"
                f"   [+] ( Optional ) Add to `nDPI/example/protos.txt`: {rule}\n"
            )

        # === If neither SNI nor certificate, use JA4 ===
        elif ja4:
            rule = f"ja4:{ja4}@{protoname}"
            instructions = (
                "\n>> To add this rule based on JA4:\n"
                "   [+] Open `nDPI/example/protos.txt`\n"
                f"   [+] Paste the following rule: {rule}\n"
            )

        with open(rules_file, "a") as f:
            f.write(f"{rule}\n{instructions}\n{'-'*62}\n")
        config.log_message(f"{rule}\n{instructions}\n{'-'*62}\n", log_file_rules)

        print(f"\n[DEBUG] Generated rule: {rule}\n{instructions}\n")

#################################################################
# End of get_info.py
#################################################################