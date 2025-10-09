
#################################################################
# File: main.py to run the entire pipeline
#################################################################

import json
import os
import subprocess
# my file
import config
import filter
import functions
import flow_processor
import threading
import constants
import coverage

# -------------------------------------------

def run_ndpi_command(cmd, output_file=None):
    if output_file:
        with open(output_file, "w") as f_out:
            subprocess.run(cmd, stdout=f_out, stderr=subprocess.DEVNULL, check=True)
    else:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

# -------------------------------------------

def run_pipeline(pcap_file, ndpi_path, output_dir, log_file, log_file_error):
    
    # clear of terminal at start
    config.clear_terminal()
    # create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # make the complete path for the rules file
    coverage_file = os.path.join(output_dir, "coverage.txt")
    config.clear_log(coverage_file)

    # Step 1: nDPI
    base, _ = os.path.splitext(os.path.basename(pcap_file))
    json_ndpi = os.path.join(output_dir, base + ".json")
    json_time_ndpi = os.path.join(output_dir, base + "_output_k.json")

    # check if on Windows ( you can delete this part if you have nDPI installed on Windows )
    if ndpi_path == 'None':
        if not os.path.exists(json_ndpi):
            config.log_message(f"JSON file from nDPI not found: {json_ndpi}", log_file_error)
        else:
            config.log_message(f">> Using existing nDPI JSON:\n\n + {json_ndpi}\n", log_file)
        if not os.path.exists(json_time_ndpi):
            config.log_message(f"JSON file from nDPI not found: {json_time_ndpi}", log_file_error)
        else:
            config.log_message(f"\n>> Using existing nDPI JSON:\n\n + {json_time_ndpi}\n", log_file)
    else:
        ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]
        ndpi_time_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-i", pcap_file, "-k", json_time_ndpi]
        
        config.log_message(f"\n>> Running nDPI first command:\n\n + {' '.join(ndpi_cmd)}\n", log_file)
        thread1 = threading.Thread(target=run_ndpi_command, args=(ndpi_cmd, json_ndpi))
        thread1.start()

        config.log_message(f"\n>> Running nDPI second command:\n\n + {' '.join(ndpi_time_cmd)}\n", log_file)
        thread2 = threading.Thread(target=run_ndpi_command, args=(ndpi_time_cmd, None))
        thread2.start()

        thread1.join()
        thread2.join()

        config.log_message(f"\n>> First nDPI JSON saved to:\n\n + {json_ndpi}\n", log_file)
        config.log_message(f"\n>> Second nDPI JSON saved to:\n\n + {json_time_ndpi}\n", log_file)

    # Step 2: filter.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    config.log_message(f"\n>> Running initial filtering ...\n\n + input file: {json_ndpi}\n + output file: {filtered_json}", log_file)
    filter.flow_filter(json_ndpi, filtered_json)   

    # Step 3: flow_processor.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    config.log_message(f"\n\n>> Running flows filtering ...\n\n + input file: {filtered_json}\n + output file: {final_output}", log_file)
    final_flows = flow_processor.flow_processor(filtered_json)

    if constants.CHECK_JA_MISSING:
        # Intermediate step: extract JA3/JA4 fingerprints and SNI values from the pcap file using tshark,
        # then save the extracted data into a temporary JSON file.
        import extract_tls_ja3_sni  # Import the module if it hasn’t been imported yet.
        tmp_cluster_file = "tmp/tshark_clusters.json"
        # Run the extraction process, which analyzes the given pcap file
        # and outputs a JSON file containing TLS clusters with JA3, JA4, and SNI information.
        extract_tls_ja3_sni.extract_tls_clusters(pcap_file, tmp_cluster_file)
        # Use the extracted JA3 and JA4 data from the tshark clusters to fill in
        # any missing fingerprint information in the 'final_flows' dataset (e.g., for HTTP flows).
        final_flows = flow_processor.fill_missing_ja_from_cluster(final_flows, tmp_cluster_file)

    with open("tmp/final_output.json", 'w') as f_out:
        json.dump(final_flows, f_out, indent=4)

    # printing flows with risk
    functions.print_risky_flows(final_flows)
    final_flows = functions.generate_rules(final_flows, final_output)

    with open(final_output, 'w') as f_out:
        json.dump(final_flows, f_out, indent=4)
    
    config.log_message(f"\n\n>> Coverage statistics save in: {coverage_file}\n", log_file)
    # Calculate and print coverage statistics
    coverage_result = coverage.calculate_coverage("tmp/final_output.json", "clusters.json")
    config.log_message(f"\n>> Coverage statistics:\n\n [+] Total packets: {coverage_result['total_packets']}\n [+] Recognized packets: {coverage_result['recognized_packets']}\n [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n [+] Total flows: {coverage_result['total_flows']}\n [+] Recognized flows: {coverage_result['recognized_flows']}\n [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", coverage_file)

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