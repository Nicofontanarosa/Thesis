import matplotlib.pyplot as plt
import numpy as np
import os
import re
import numpy as np

def plot_and_save_coverage_graphs(stats, output_dir="validation_results"):
    # Crea la cartella se non esiste
    os.makedirs(output_dir, exist_ok=True)

    methods = ["ndpi", "gt", "system"]
    method_labels = ["nDPI only", "nDPI + GT", "nDPI + My System"]
    colors = [("#1f77b4", "#aec7e8"), ("#2ca02c", "#98df8a"), ("#d62728", "#ff9896")]

    apps = list(stats.keys())
    x = np.arange(len(apps))
    bar_width = 0.35

    for i, method in enumerate(methods):
        packet_cov = []
        flow_cov = []

        for app in apps:
            app_data = stats.get(app, {}).get(method, {})
            packet_cov.append(app_data.get("packet_coverage", 0))
            flow_cov.append(app_data.get("flow_coverage", 0))

        fig, ax = plt.subplots(figsize=(15, 6))
        ax.bar(x - bar_width/2, packet_cov, bar_width, label="Packets (%)", color=colors[i][0])
        ax.bar(x + bar_width/2, flow_cov, bar_width, label="Flows (%)", color=colors[i][1])

        ax.set_xlabel("Applications")
        ax.set_ylabel("Coverage (%)")
        ax.set_title(f"Coverage Comparison – {method_labels[i]}")
        ax.set_xticks(x)
        ax.set_xticklabels(apps, rotation=45, ha="right", fontsize=9)
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.6)

        plt.tight_layout()

        # 🔹 Salva l'immagine come screenshot
        output_path = os.path.join(output_dir, f"coverage_{method}.png")
        plt.savefig(output_path, dpi=300)
        plt.close(fig)

        print(f"[+] Saved: {output_path}")

def plot_combined_coverage(stats, output_dir="validation_results"):
    os.makedirs(output_dir, exist_ok=True)

    methods = ["ndpi", "gt", "system"]
    method_labels = ["nDPI only", "nDPI + GT", "nDPI + My System"]
    colors = ["#1f77b4", "#2ca02c", "#d62728"]  # blu, verde, rosso

    apps = list(stats.keys())
    x = np.arange(len(apps))
    bar_width = 0.25
    alpha = 0.6  # trasparenza

    fig, ax = plt.subplots(figsize=(18, 7))

    # Disegna i 3 metodi sovrapposti
    for i, method in enumerate(methods):
        packet_cov = []
        flow_cov = []

        for app in apps:
            app_data = stats.get(app, {}).get(method, {})
            packet_cov.append(app_data.get("packet_coverage", 0))
            flow_cov.append(app_data.get("flow_coverage", 0))

        # le barre saranno leggermente spostate per non coprirsi completamente
        offset = (i - 1) * bar_width / 2

        ax.bar(
            x + offset - bar_width/2, packet_cov, bar_width,
            label=f"{method_labels[i]} – Packets", color=colors[i], alpha=alpha
        )
        ax.bar(
            x + offset + bar_width/2, flow_cov, bar_width,
            label=f"{method_labels[i]} – Flows", color=colors[i], alpha=alpha/1.5
        )

    ax.set_xlabel("Applications")
    ax.set_ylabel("Coverage (%)")
    ax.set_title("Coverage Comparison: nDPI vs GT vs My System")
    ax.set_xticks(x)
    ax.set_xticklabels(apps, rotation=45, ha="right", fontsize=9)
    ax.legend(fontsize=9)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()

    # 🔹 Salva l’immagine combinata
    output_path = os.path.join(output_dir, "coverage_combined.png")
    plt.savefig(output_path, dpi=300)
    plt.close(fig)

    print(f"[+] Saved combined coverage graph: {output_path}")

def extract_coverage_stats(base_dir="coverage"):
    applications = [
        "Doctor_App", "Trenitalia", "Subito", "Strava", "Notion", "MarioKart", "MarinoBus", 
        "Mapy", "LidlPlus", "Klarna", "JustEat", "Glovo", "Alza", "Vinted", "Expedia", "Hostelworld",
        "Austrian", "Warframe", "AviraVPN", "FireNetVPN", "HideVPN", "HoxxVPN",
        "PlanetVPN", "UltrasurfVPN", "XrpTunnelVPN"
    ]

    # sottocartelle dove cercare i file
    subdirs = {
        "ndpi": os.path.join(base_dir, "coveragenDPIonly"),
        "gt": os.path.join(base_dir, "coverageGT"),
        "system": base_dir  # cartella principale
    }

    # regex per trovare le percentuali
    regex_packet = re.compile(r"Coverage\s*\(%\):\s*([\d.]+)")
    regex_flow = re.compile(r"Flow coverage\s*\(%\):\s*([\d.]+)")

    data = {}

    for app in applications:
        app_data = {}
        for key, folder in subdirs.items():
            filepath = os.path.join(folder, f"{app}.txt")

            if not os.path.exists(filepath):
                print(f"[WARN] File mancante: {filepath}")
                continue

            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            packet_match = regex_packet.search(content)
            flow_match = regex_flow.search(content)

            if packet_match and flow_match:
                app_data[key] = {
                    "packet_coverage": float(packet_match.group(1)),
                    "flow_coverage": float(flow_match.group(1))
                }
            else:
                print(f"[WARN] Dati incompleti in {filepath}")

        data[app] = app_data

    return data

stats = extract_coverage_stats()
plot_and_save_coverage_graphs(stats)
plot_combined_coverage(stats)