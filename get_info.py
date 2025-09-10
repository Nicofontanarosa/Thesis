
#################################################################
# File: get_info.py
#################################################################

import requests
import whois as whois
import json
import os
# my file
import config

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

def print_rules(flows, protocol_name, rules_file):

    # set to keep unique SNI values
    sni_set = set(flows)

    # no SNI found
    if not sni_set:
        return None
    
    # build nDPI rule
    host_entries = ",".join([f'host:"{sni}"' for sni in sorted(sni_set)])
    rule = f"{host_entries}@{protocol_name.capitalize()}"

    with open(rules_file, "a") as f:
        f.write(f"{rule}\n")

    print(f"\nRules saved to {rules_file}:\n{rule}\n")

def classify_domains(domains, output_file):

    output_folder = os.path.dirname(output_file)
    # make the complete path for the rules file
    rules_file = os.path.join(output_folder, "rules.txt")

    org_to_snis = {}

    for d in domains:

        ai = False

        try:
            w = whois.whois(d)
            org = w.get("registrant_organization") or w.get("admin_organization") or w.get("org")
            
            if org is None or org.lower() in config.REDACTED_ORGS:
                if os.name == 'nt':
                    org = classify_domain_AI(d)
                else: org = "unknown"
                ai = True
            else:
                org = org.lower()

            if org not in org_to_snis:
                org_to_snis[org] = []
            org_to_snis[org].append(d)

            if ai:
                print(f"{d} → AI: {org}")
            else:
                print(f"{d} → whois: {org}")
        except Exception as e:
            print(f"{d} → errore whois")
            if "unknown" not in org_to_snis:
                org_to_snis["unknown"] = []
            org_to_snis["unknown"].append(d)

    print("\n")
    for org, snis in org_to_snis.items():
        print_rules(snis, org, rules_file)

#################################################################
# End of get_info.py
#################################################################

