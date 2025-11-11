
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

def run_pipeline(pcap_file, ndpi_path, output_dir, protoname, log_file, log_file_error, log_params):
    
    # clear of terminal at start
    config.clear_terminal()
    # create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    config.log_message(f"\n>> Here there are all parameters set by user:\n\n", log_params)
    config.log_message(f"\n[+] PROTOCOLS: {constants.PROTOCOLS}", log_params)
    config.log_message(f"\n[+] KEYS_BY_PROTOCOL: {constants.KEYS_BY_PROTOCOL}", log_params)
    config.log_message(f"\n[+] TOP_PERCENT: {constants.TOP_PERCENT}", log_params)
    config.log_message(f"\n[+] SNI_MAX_DOMAIN: {constants.SNI_MAX_DOMAIN}", log_params)
    config.log_message(f"\n[+] SHOW_NDPI_PROTOCOLS: {constants.SHOW_NDPI_PROTOCOLS}", log_params)
    print(f"\n>> Here there are all parameters set by user:\n")
    print(f"\n[+] PROTOCOLS: {constants.PROTOCOLS}")
    print(f"\n[+] KEYS_BY_PROTOCOL: {constants.KEYS_BY_PROTOCOL}")
    print(f"\n[+] TOP_PERCENT: {constants.TOP_PERCENT}")
    print(f"\n[+] SNI_MAX_DOMAIN: {constants.SNI_MAX_DOMAIN}")
    print(f"\n[+] SHOW_NDPI_PROTOCOLS: {constants.SHOW_NDPI_PROTOCOLS}")

    # make the complete path for the coverage file
    coverage_file = os.path.join(output_dir, "coverage.txt")
    config.clear_log(coverage_file)
    config.clear_log("tmp/coverage.txt")
    # make the complete path for the rules file
    rules_file = os.path.join(output_dir, "rules.txt")
    config.clear_log(rules_file)

    # Step 1: nDPI
    base, _ = os.path.splitext(os.path.basename(pcap_file))
    json_ndpi = os.path.join(output_dir, base + ".json")

    # check if on Windows ( you can delete this part if you have nDPI installed on Windows )
    if ndpi_path == 'None':
        if not os.path.exists(json_ndpi):
            config.log_message(f"JSON file from nDPI not found: {json_ndpi}", log_file_error)
        else:
            config.log_message(f">> Using existing nDPI JSON:\n\n [+] {json_ndpi}\n", log_file)
    else:
        ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]

        config.log_message(f"\n>> Running nDPI first command:\n\n [+] {' '.join(ndpi_cmd)}\n", log_file)
        thread1 = threading.Thread(target=run_ndpi_command, args=(ndpi_cmd, json_ndpi))
        thread1.start()

        thread1.join()

        config.log_message(f"\n>> First nDPI JSON saved to:\n\n [+] {json_ndpi}\n", log_file)

    # Step 2: filter.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    config.log_message(f"\n>> Running initial filtering ...\n\n [+] input file: {json_ndpi}\n [+] output file: {filtered_json}", log_file)
    filter.flow_filter(json_ndpi, filtered_json)   

    # Step 3: flow_processor.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    config.log_message(f"\n\n>> Running flows filtering ...\n\n [+] input file: {filtered_json}\n [+] output file: {final_output}", log_file)
    final_flows = flow_processor.flow_processor(filtered_json, tmp = True)
    final_all_flows = flow_processor.flow_processor(json_ndpi, tmp = False)  

    with open("tmp/final_complete_output.json", 'w') as f_out:
        json.dump(final_all_flows, f_out, indent=4)

    if constants.CHECK_JA_MISSING:
        # Intermediate step: extract JA3/JA4 fingerprints and SNI values from the pcap file using tshark,
        # then save the extracted data into a temporary JSON file.
        import extract_tls_ja3_sni  # Import the module if it hasn’t been imported yet.
        tmp_groups_file = "tmp/tshark_groups.json"
        # Run the extraction process, which analyzes the given pcap file
        # and outputs a JSON file containing TLS groups with JA3, JA4, and SNI information.
        extract_tls_ja3_sni.extract_tls_groups(pcap_file, tmp_groups_file)
        # Use the extracted JA3 and JA4 data from the tshark groups to fill in
        # any missing fingerprint information in the 'final_flows' dataset (e.g., for HTTP flows).
        final_flows = flow_processor.fill_missing_ja_from_groups(final_flows, tmp_groups_file)

    with open("tmp/final_output.json", 'w') as f_out:
        json.dump(final_flows, f_out, indent=4)

    # printing flows with risk
    functions.print_risky_flows(final_flows)

    final_flows = functions.generate_rules(final_flows, rules_file, protoname)

    with open(final_output, 'w') as f_out:
        json.dump(final_flows, f_out, indent=4)
    
    config.log_message(f"\n\n>> Coverage statistics save in: {coverage_file}", log_file)
    # calculate and print coverage statistics for filtered flows
    coverage_result = coverage.calculate_coverage("tmp/final_output.json", "tmp/groups.json")
    # log to coverage file for filtered flows
    config.log_message(f"\n>> Coverage statistics for filtered flows:\n\n [+] Total packets: {coverage_result['total_packets']}\n [+] Recognized packets: {coverage_result['recognized_packets']}\n [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n [+] Total flows: {coverage_result['total_flows']}\n [+] Recognized flows: {coverage_result['recognized_flows']}\n [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", coverage_file)
    config.log_message(f"\n>> Coverage statistics for filtered flows:\n\n [+] Total packets: {coverage_result['total_packets']}\n [+] Recognized packets: {coverage_result['recognized_packets']}\n [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n [+] Total flows: {coverage_result['total_flows']}\n [+] Recognized flows: {coverage_result['recognized_flows']}\n [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", "tmp/coverage.txt")
    # also log to rules file for filtered flows
    config.log_message(f"\n# Coverage statistics for filtered flows:\n\n# [+] Total packets: {coverage_result['total_packets']}\n# [+] Recognized packets: {coverage_result['recognized_packets']}\n# [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n# [+] Total flows: {coverage_result['total_flows']}\n# [+] Recognized flows: {coverage_result['recognized_flows']}\n# [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", rules_file)
    config.log_message(f"\n# Coverage statistics for filtered flows:\n\n# [+] Total packets: {coverage_result['total_packets']}\n# [+] Recognized packets: {coverage_result['recognized_packets']}\n# [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n# [+] Total flows: {coverage_result['total_flows']}\n# [+] Recognized flows: {coverage_result['recognized_flows']}\n# [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", "tmp/rules.txt")
    
    # calculate and print coverage statistics for all flows
    coverage_result = coverage.calculate_coverage("tmp/final_complete_output.json", "tmp/groups.json")
    # log to coverage file for all flows
    config.log_message(f"\n\n>> Coverage statistics for all flows:\n\n [+] Total packets: {coverage_result['total_packets']}\n [+] Recognized packets: {coverage_result['recognized_packets']}\n [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n [+] Total flows: {coverage_result['total_flows']}\n [+] Recognized flows: {coverage_result['recognized_flows']}\n [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", coverage_file)
    config.log_message(f"\n\n>> Coverage statistics for all flows:\n\n [+] Total packets: {coverage_result['total_packets']}\n [+] Recognized packets: {coverage_result['recognized_packets']}\n [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n [+] Total flows: {coverage_result['total_flows']}\n [+] Recognized flows: {coverage_result['recognized_flows']}\n [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", "tmp/coverage.txt")
    # also log to rules file for all flows
    config.log_message(f"\n\n# Coverage statistics for all flows:\n\n# [+] Total packets: {coverage_result['total_packets']}\n# [+] Recognized packets: {coverage_result['recognized_packets']}\n# [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n# [+] Total flows: {coverage_result['total_flows']}\n# [+] Recognized flows: {coverage_result['recognized_flows']}\n# [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", rules_file)
    config.log_message(f"\n\n# Coverage statistics for all flows:\n\n# [+] Total packets: {coverage_result['total_packets']}\n# [+] Recognized packets: {coverage_result['recognized_packets']}\n# [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n# [+] Total flows: {coverage_result['total_flows']}\n# [+] Recognized flows: {coverage_result['recognized_flows']}\n# [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}", "tmp/rules.txt")

    config.log_message(f"\n\n>> All removed flows save in: .\\tmp\\removed_flows.json", log_file)

    return coverage_result

def main_pipeline(pcap, ndpi, output, protoname):

    # at the beginning of run_pipeline or right after the imports
    log_file = "tmp/initialization.txt"
    log_file_error = "tmp/errors.txt"
    log_params = "tmp/parameters.txt"
    config.clear_log(log_file)
    config.clear_log(log_file_error)
    config.clear_log(log_params)

    coverage_result = run_pipeline(pcap, ndpi, output, protoname, log_file, log_file_error, log_params)

    return coverage_result

#################################################################
# End of main.py
#################################################################