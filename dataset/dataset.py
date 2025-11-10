
#################################################################
# File: dataset.py extracts domain from a C-style static array in the input file and writes them as a JSON dataset
#################################################################

import re
import json
import sys

# -------------------------------------------

def extract_domains(input_file, output_file):

    if input_file == 'None':

        # regex pattern to match domain strings inside braces
        domain_pattern = re.compile(r'^\s*\{\s*"([^"]+)"\s*,')

        domains = []
        inside_block = False  
        # track if we're inside the relevant static array

        with open(input_file, 'r') as fin:
            for line in fin:
                # detect the start of the host_match or category_match arrays
                if "static ndpi_protocol_match host_match[]" in line or "static ndpi_category_match category_match[]" in line:
                    inside_block = True
                    continue

                # process lines inside the block
                if inside_block:
                    # Ddetect the end of the array
                    if line.strip().startswith("};"):
                        inside_block = False
                        continue

                    # match domain strings
                    match = domain_pattern.match(line)
                    if match:
                        domains.append(match.group(1))

        # remove duplicates and sort the domains
        unique_domains = sorted(set(domains))

        # save domains to JSON
        data = {"domains": unique_domains}
        with open(output_file, 'w') as fout:
            json.dump(data, fout, indent=2)

# -------------------------------------------

def run():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input> <output>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # extract domains from the input file to the first output dataset
    extract_domains(input_file, output_file)

    # process a temporary JSON dataset (temp.json) to create datasetTLD.json
    input_file = "temp.json"
    output_file = "datasetTLD.json"

    with open(input_file, "r") as f:
        data = json.load(f)

    domains = data.get("domains", [])
    # remove duplicates and sort
    domains_sorted = sorted(set(domains))
    data["domains"] = domains_sorted

    # write the cleaned dataset to datasetTLD.json
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    run()

#################################################################
# End of dataset.py
#################################################################