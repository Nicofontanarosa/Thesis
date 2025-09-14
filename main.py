
#################################################################
# File: main.py to run the entire pipeline
#################################################################

import os
import subprocess
import argparse
# -------------------------------------------
import config
import filter
import functions
import flow_processor

# mettere controllo che se l'sni appare nel domain prendere il plein text per visualizzare il nome del protocollo

# cambiare il tutto e chiamare solo funzioni

def run_pipeline(pcap_file, ndpi_path, output_dir):
    
    # clear of terminal at start
    config.clear_terminal()
    # create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: nDPI
    base, _ = os.path.splitext(os.path.basename(pcap_file))
    json_ndpi = os.path.join(output_dir, base + ".json")

    # check if on Windows ( you can delete this part if you have nDPI installed on Windows)
    if ndpi_path == 'None':
        if not os.path.exists(json_ndpi):
            raise FileNotFoundError(f"JSON file from nDPI not found: {json_ndpi}")
        else:
            config.log_message(f"- Using existing nDPI JSON: {json_ndpi}", log_file)
    else:
        ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]
        config.log_message(f"\n- Running nDPI: {' '.join(ndpi_cmd)}", log_file)
        with open(json_ndpi, "w") as f_out:
            subprocess.run(ndpi_cmd, stdout=f_out, check=True)
        config.log_message(f"- nDPI JSON saved to: {json_ndpi}", log_file)

    # Step 2: filter.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    config.log_message(f"\n- Running initial filtering: input file ({json_ndpi} | output file ({filtered_json})", log_file)
    filter.flow_filter(json_ndpi, filtered_json)   

    # Step 3: flow_processor.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    config.log_message(f"\n- Running initial filtering: input file ({filtered_json} | output file ({final_output})", log_file)
    final_flows = flow_processor.flow_processor(filtered_json, final_output)

    functions.print_flows(final_flows)
    functions.generate_rules(final_flows, final_output)
    
if __name__ == "__main__":

    # At the beginning of run_pipeline or right after the imports
    log_file = "tmp/initialization.txt"
    config.clear_log(log_file)

    parser = argparse.ArgumentParser(description="Pipeline to process PCAP via nDPI, filter, flow_processor")
    parser.add_argument("-p", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-n", "--ndpi", required=True, help="Path to nDPI folder")
    parser.add_argument("-o", "--output", required=True, help="Output folder for results")
    args = parser.parse_args()
    
    # Determine python command depending on OS
    python_cmd = "py" if os.name == "nt" else "python3"

    #subprocess.Popen([python_cmd, "flow_viewer_textual.py"])
    run_pipeline(args.pcap, args.ndpi, args.output)

#################################################################
# End of main.py
#################################################################