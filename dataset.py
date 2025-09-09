# -------------------------------------------
import config
import re
import json
# -------------------------------------------

# parsing args
args = config.get_args()
input_file = args.input_file
output_file = args.output

# print files used
config.print_files(input_file, output_file)

# -------------------------------------------

def extract_domains(input_file, output_file):

    domain_pattern = re.compile(r'^\s*\{\s*"([^"]+)"\s*,')
    
    domains = []
    inside_block = False

    with open(input_file, 'r') as fin:
        for line in fin:
            if "static ndpi_protocol_match host_match[]" in line or "static ndpi_category_match category_match[]" in line:
                inside_block = True
                continue

            if inside_block:
                if line.strip().startswith("};"):
                    inside_block = False
                    continue

                match = domain_pattern.match(line)
                if match:
                    domains.append(match.group(1))

    unique_domains = sorted(set(domains))

    # scrivo in formato JSON
    data = {"domains": unique_domains}
    with open(output_file, 'w') as fout:
        json.dump(data, fout, indent=2)

    print(f"[+] Estratti {len(domains)} domini, scritti {len(unique_domains)} unici in {output_file}")



extract_domains(input_file, output_file)