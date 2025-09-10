
#################################################################
# File: dataset.py extracts domain from a C-style static array in the input file and writes them as a JSON dataset
#################################################################

import config
import re
import json
# -------------------------------------------

# Parse command-line arguments
args = config.get_args()
input_file = args.input_file
output_file = args.output

# Print the input and output file paths being used
config.print_files(input_file, output_file)

# -------------------------------------------

def extract_domains(input_file, output_file):

    # Regex pattern to match domain strings inside braces
    domain_pattern = re.compile(r'^\s*\{\s*"([^"]+)"\s*,')

    domains = []
    inside_block = False  
    # Track if we're inside the relevant static array

    with open(input_file, 'r') as fin:
        for line in fin:
            # Detect the start of the host_match or category_match arrays
            if "static ndpi_protocol_match host_match[]" in line or "static ndpi_category_match category_match[]" in line:
                inside_block = True
                continue

            # Process lines inside the block
            if inside_block:
                # Detect the end of the array
                if line.strip().startswith("};"):
                    inside_block = False
                    continue

                # Match domain strings
                match = domain_pattern.match(line)
                if match:
                    domains.append(match.group(1))

    # Remove duplicates and sort the domains
    unique_domains = sorted(set(domains))

    # Save domains to JSON
    data = {"domains": unique_domains}
    with open(output_file, 'w') as fout:
        json.dump(data, fout, indent=2)

    print(f"[+] Extracted {len(domains)} domains, wrote {len(unique_domains)} unique domains to {output_file}")

# -------------------------------------------

# Extract domains from the input file to the first output dataset
extract_domains(input_file, output_file)

# -------------------------------------------
# Process a temporary JSON dataset (temp.json) to create datasetTLD.json
input_file = "temp.json"
output_file = "datasetTLD.json"

with open(input_file, "r") as f:
    data = json.load(f)

domains = data.get("domains", [])
# Remove duplicates and sort
domains_sorted = sorted(set(domains))
data["domains"] = domains_sorted

# Write the cleaned dataset to datasetTLD.json
with open(output_file, "w") as f:
    json.dump(data, f, indent=2)

#################################################################
# End of dataset.py
#################################################################