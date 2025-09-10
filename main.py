
#################################################################
# File: main.py to run the entire pipeline
#################################################################

import os
import subprocess
import argparse
# -------------------------------------------

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def run_pipeline(pcap_file, ndpi_path, output_dir):
    
    # Clear of terminal at start
    clear_terminal()
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: nDPI
    json_ndpi = os.path.join(output_dir, os.path.basename(pcap_file).replace(".pcapng", ".json"))

    # Check if on Windows ( you can delete this part if you have nDPI installed on Windows)
    if os.name == 'nt':
        if not os.path.exists(json_ndpi):
            raise FileNotFoundError(f"JSON file from nDPI not found: {json_ndpi}")
        else:
            print(f"Using existing nDPI JSON: {json_ndpi}")
    else:
        ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]
        print(f"\nRunning nDPI: {' '.join(ndpi_cmd)}")
        with open(json_ndpi, "w") as f_out:
            subprocess.run(ndpi_cmd, stdout=f_out, check=True)
        print(f"nDPI JSON saved to: {json_ndpi}")

    # Step 2: filter.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    filter_cmd = ["python3", "filter.py", json_ndpi, "-o", filtered_json]
    print(f"\nRunning filter.py: {' '.join(filter_cmd)}")
    subprocess.run(filter_cmd, check=True)

    # Step 3: flow_processor.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    flow_processor_cmd = ["python3", "flow_processor.py", filtered_json, "-o", final_output]
    print(f"\nRunning flow_processor.py: {' '.join(flow_processor_cmd)}")
    subprocess.run(flow_processor_cmd, check=True)

    return final_output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline to process PCAP via nDPI, filter, flow_processor")
    parser.add_argument("-p", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-n", "--ndpi", required=True, help="Path to nDPI folder")
    parser.add_argument("-o", "--output", required=True, help="Output folder for results")
    args = parser.parse_args()

    run_pipeline(args.pcap, args.ndpi, args.output)

#################################################################
# End of main.py
#################################################################