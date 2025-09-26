
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

log_file_rules = "tmp/rules.txt"
config.clear_log(log_file_rules)

def classify_domain_AI(domain):

    # Set up the base URL for the local Ollama API
    url = "http://localhost:11434/api/chat"

    # Define the model and the input prompt
    prompt = f"You are a traffic monitoring assistant. Tell me in a COUPLE OF WORD the name of the service / application to which this domain belongs: {domain}"

    # Define the payload
    payload = {
        "model": "gemma3",  # Replace with the model name you're using
        "messages": [{"role": "user", "content": prompt}]
    }

    # Send the HTTP POST request with streaming enabled
    response = requests.post(url, json=payload)
    message = ""
    # Check the response status
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

def classify_domains(clusters, output_file):

    output_folder = os.path.dirname(output_file)
    # make the complete path for the rules file
    rules_file = os.path.join(output_folder, "rules.txt")
    config.clear_log(rules_file)

    for cluster in clusters:
        snis = cluster.get("sni_list", [])
        
        if constants.SHOW_NAME_HINT:

            whois_orgs = set()
            ai_orgs = set()

            for d in snis:
                try:
                    w = whois.whois(d)
                    org = w.get("registrant_organization") or w.get("admin_organization") or w.get("org")
                    #print(f"\n---{org.lower()}---{ 'true' if org.lower() in constants.REDACTED_ORGS else 'false'}----")

                    if org is None or org.lower() in constants.REDACTED_ORGS:
                        if os.name == 'nt':
                            org = "unknown"
                            orgai = classify_domain_AI(d)
                        else: 
                            orgai = "unknown"
                            org = "unknown"
                    else:
                        if os.name == 'nt':
                            orgai = classify_domain_AI(d)
                        else:
                            orgai = "unknown"
                        org = org.lower()

                    whois_orgs.add(org)
                    ai_orgs.add(orgai)

                    print(f"{d} → AI: {orgai} & whois: {org}")

                except Exception as e:
                    orgai = classify_domain_AI(d)
                    ai_orgs.add(orgai)
                    print(f"{d} → AI: {orgai}")

            org = org.split()[0] if org else org
            orgai = orgai.split()[0] if orgai else orgai
            #print(f"Classified orgs for cluster {snis} → AI: {orgai} & whois: {org}")
            host_entries = ",".join([f'host:"{sni}"' for sni in sorted(snis)])

            if constants.SHOW_GUESS_SNI:

                if (org != "unknown" and org):
                    proto = org
                elif (orgai != "unknown" and orgai):
                    proto = orgai
                else:
                    proto = "unknown"

                # regola host
                rule = f"{host_entries}@{proto}"

            else:
                # genera chiave combinata: whois + AI se entrambi presenti
                whois_str = ", ".join(sorted(whois_orgs)) if whois_orgs else ""
                ai_str = ", ".join(sorted(ai_orgs)) if ai_orgs else "unknown"

                # regola host
                rule = f"{host_entries}@whois: {whois_str} & AI: {ai_str}"

        else:
            # genera regola solo con host
            host_entries = ",".join([f'host:"{sni}"' for sni in sorted(snis)])
            rule = f"{host_entries}@"

        with open(rules_file, "a") as f:
            f.write(f"{rule}\n")
        config.log_message(f"{rule}\n", log_file_rules)

        print(f"\nRules saved to {rules_file}:\n{rule}\n")

#################################################################
# End of get_info.py
#################################################################