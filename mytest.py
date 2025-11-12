import os
import subprocess
import coverage
import config
import shutil

def run_coverage_tests():
    # Tutte le applicazioni da testare
    applications = [
        "Doctor_App", "Trenitalia", "Subito", "Strava", "Notion", "MarioKart", "MarinoBus", "Ryanair", "Crunchyroll",
        "Mapy",  "LidlPlus", "Klarna", "JustEat", "Glovo", "Alza", "Vinted", "Expedia", "Hostelworld",
        "Austrian", "Warframe", "AviraVPN", "FireNetVPN", "HideVPN", "HoxxVPN",
        "PlanetVPN", "UltrasurfVPN", "XrpTunnelVPN"
    ]

    # Percorso base (modificalo se serve)
    base_pcap_path = r"C:\Programs\Thesis\pcapng"
    test_base_path = r".\test"
    log_base_path = r"coverage"

    # Crea la cartella coverage se non esiste
    os.makedirs(log_base_path, exist_ok=True)

    # Scorri tutte le applicazioni
    for app in applications:
        print(f"\n   [+] Testing application: {app}")

        # Costruisci i percorsi per ogni app
        pcap_path = os.path.join(base_pcap_path, f"{app}.pcapng")
        test_path = os.path.join(test_base_path, app)
        log_file_path = os.path.join(log_base_path, f"{app}.txt")
        log_rule_file_path = os.path.join(log_base_path, f"rule{app}.txt")

        # Esegui il comando di debug
        command = ["py", ".\\debug.py", pcap_path, "None", test_path, app]
        print(f"   [DEBUG] Running command: {' '.join(command)}")
        subprocess.run(command, check=True)

        # Calcola la coverage
        coverage_result = coverage.calculate_coverage("tmp/final_complete_output.json", "tmp/groups.json")

        # Log dei risultati
        message = (
            f"\n\n>> Coverage statistics for using nDPI only:\n\n"
            f" [+] Total packets: {coverage_result['total_packets']}\n"
            f" [+] Recognized packets: {coverage_result['recognized_packets']}\n"
            f" [+] Coverage (%): {coverage_result['packet_coverage_percent']}\n"
            f" [+] Total flows: {coverage_result['total_flows']}\n"
            f" [+] Recognized flows: {coverage_result['recognized_flows']}\n"
            f" [+] Flow coverage (%): {coverage_result['flow_coverage_percent']}"
        )

        config.clear_log(log_file_path)
        config.log_message(message, log_file_path)

        print(f"   [+] Coverage results saved in: {log_file_path}")

        try:
            shutil.copyfile("tmp/rules.txt", log_rule_file_path)
            print(f"[+] Copied tmp/rules.txt → {log_rule_file_path}")
        except Exception as e:
            print(f"[!] Failed to copy: {e}")

if __name__ == "__main__":
    run_coverage_tests()
