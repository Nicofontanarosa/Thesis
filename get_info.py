
#################################################################
# File: get_info.py
#################################################################

import ollama
import requests
import whois
from ipwhois import IPWhois

def classify_domain_AI(domain):

    # Define the model and the input prompt
    prompt = f"You are a traffic monitoring assistant. Tell me in ONE WORD the name of the service / application to which this domain belongs: {domain}"

    # Send the query to the model
    response = client.generate(model="gemma3", prompt=prompt)

    return response.response

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

    # Initialize the Ollama client
    client = ollama.Client()

    org_to_snis = {}

    for d in domains:
        try:
            w = whois.whois(d)
            org = w.get("registrant_organization") or w.get("admin_organization") or w.get("org")
            
            if org is None or org.lower() == "redacted for privacy":
                org = classify_domain_AI(d)
            else:
                org = org.lower()

            if org not in org_to_snis:
                org_to_snis[org] = []
            org_to_snis[org].append(d)

            print(f"{d} → whois: {org}")
        except Exception as e:
            print(f"{d} → errore whois: {e}")

    for org, snis in org_to_snis.items():
        print_rules(snis, org)

#################################################################
# End of get_info.py
#################################################################

