import os
import subprocess
import argparse

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def run_pipeline(pcap_file, ndpi_path, output_dir):
    
    # Clear of terminal at start
    clear_terminal()
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: nDPI
    json_ndpi = os.path.join(output_dir, os.path.basename(pcap_file).replace(".pcapng", ".json"))
    ndpi_cmd = [os.path.join(ndpi_path, "example/ndpiReader"), "-v", "2", "-i", pcap_file]
    print(f"\nRunning nDPI: {' '.join(ndpi_cmd)}")
    with open(json_ndpi, "w") as f_out:
        subprocess.run(ndpi_cmd, stdout=f_out, check=True)
    print(f"nDPI JSON saved to: {json_ndpi}")

    # Step 2: filtro.py
    filtered_json = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_filtered.json"))
    filtro_cmd = ["python3", "filtro.py", json_ndpi, "-o", filtered_json]
    print(f"\nRunning filtro.py: {' '.join(filtro_cmd)}")
    subprocess.run(filtro_cmd, check=True)

    # Step 3: clustering.py
    final_output = os.path.join(output_dir, os.path.basename(json_ndpi).replace(".json", "_output.json"))
    clustering_cmd = ["python3", "clustering.py", filtered_json, "-o", final_output]
    print(f"\nRunning clustering.py: {' '.join(clustering_cmd)}")
    subprocess.run(clustering_cmd, check=True)

    return final_output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline to process PCAP via nDPI, filter, clustering")
    parser.add_argument("-p", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-n", "--ndpi", required=True, help="Path to nDPI folder")
    parser.add_argument("-o", "--output", required=True, help="Output folder for results")
    args = parser.parse_args()

    run_pipeline(args.pcap, args.ndpi, args.output)
