
#################################################################
# File: main.py to run the entire pipeline
#################################################################

import os
import subprocess
# my file
import config
import filter
import functions
import flow_processor

def run_pipeline(pcap_file, ndpi_path, output_dir, log_file, log_file_error):
    
    # clear of terminal at start
    config.clear_terminal()
    # create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: nDPI
    base, _ = os.path.splitext(os.path.basename(pcap_file))
    json_ndpi = os.path.join(output_dir, base + ".json")
    json_time_ndpi = os.path.join(output_dir, base + "_k.json")

    # check if on Windows ( you can delete this part if you have nDPI installed on Windows)
    if ndpi_path == 'None':
        if not os.path.exists(json_ndpi):
            config.log_message(f"JSON file from nDPI not found: {json_ndpi}", log_file_error)
        else:
            config.log_message(f">> Using existing nDPI JSON:\n\n + {json_ndpi}\n", log_file)
        if not os.path.exists(json_time_ndpi):
            config.log_message(f"JSON file from nDPI not found: {json_time_ndpi}", log_file_error)
        else:
            config.log_message(f">> Using existing nDPI JSON:\n\n + {json_time_ndpi}\n", log_file)
    else:
        ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]
        ndpi_time_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-k", "-i", pcap_file]
        config.log_message(f"\n>> Running nDPI:\n\n + {' '.join(ndpi_cmd)}\n", log_file)
        with open(json_ndpi, "w") as f_out:
            subprocess.run(ndpi_cmd, stdout=f_out, check=True)
        config.log_message(f">> nDPI JSON saved to:\n\n + {json_ndpi}\n", log_file)
        config.log_message(f"\n>> Running nDPI:\n\n + {' '.join(ndpi_time_cmd)}\n", log_file)
        with open(json_time_ndpi, "w") as f_out:
            subprocess.run(ndpi_cmd, stdout=f_out, check=True)
        config.log_message(f">> nDPI JSON saved to:\n\n + {json_time_ndpi}\n", log_file)

    # Step 2: filter.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    config.log_message(f"\n>> Running initial filtering ...\n\n + input file: {json_ndpi}\n + output file: {filtered_json}", log_file)
    filter.flow_filter(json_ndpi, filtered_json)   

    # Step 3: flow_processor.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    config.log_message(f"\n\n>> Running initial filtering ...\n\n + input file: {filtered_json}\n + output file: {final_output}", log_file)
    final_flows = flow_processor.flow_processor(filtered_json, final_output)

    #functions.print_flows(final_flows)
    functions.generate_rules(final_flows, final_output)
    
def main_pipeline(pcap, ndpi, output):

    # At the beginning of run_pipeline or right after the imports
    log_file = "tmp/initialization.txt"
    log_file_error = "tmp/errors.txt"
    config.clear_log(log_file)
    config.clear_log(log_file_error)

    run_pipeline(pcap, ndpi, output, log_file, log_file_error)

#################################################################
# End of main.py
#################################################################