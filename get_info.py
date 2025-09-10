
#################################################################
# File: get_info.py
#################################################################

import requests
import whois as whois
import json

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

def print_rules(flows, protocol_name):

     # Set to keep unique SNI values
    sni_set = set(flows)

    # No SNI found
    if not sni_set:
        return None
    
    # Build nDPI rule
    host_entries = ",".join([f'host:"{sni}"' for sni in sorted(sni_set)])
    rule = f"{host_entries}@{protocol_name.capitalize()}"
    print(f"\033[1m{rule}\033[0m")

def classify_domains(domains):

    org_to_snis = {}

    for d in domains:

        ai = False

        try:
            w = whois.whois(d)
            org = w.get("registrant_organization") or w.get("admin_organization") or w.get("org")
            
            if org is None or org.lower() == "redacted for privacy":
                org = classify_domain_AI(d)
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
            print(f"{d} → errore whois: {e}")

    print("\n")
    for org, snis in org_to_snis.items():
        print_rules(snis, org)

#################################################################
# End of get_info.py
#################################################################

