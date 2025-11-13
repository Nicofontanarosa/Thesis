import matplotlib.pyplot as plt
import numpy as np
import os
import re
import numpy as np
import seaborn as sns

applications_data = [
    {"name": "Doctor_App", "total": 36, "tp": 18, "tn": 18, "fp": 0, "fn": 0},
    {"name": "Trenitalia", "total": 33, "tp": 16, "tn": 16, "fp": 1, "fn": 0},
    {"name": "Subito", "total": 59, "tp": 31, "tn": 28, "fp": 0, "fn": 0},
    {"name": "Strava", "total": 95, "tp": 68, "tn": 27, "fp": 0, "fn": 0},
    {"name": "Notion", "total": 54, "tp": 30, "tn": 19, "fp": 0, "fn": 5},
    {"name": "MarioKart", "total": 52, "tp": 48, "tn": 4, "fp": 0, "fn": 0},
    {"name": "MarinoBus", "total": 19, "tp": 7, "tn": 11, "fp": 1, "fn": 0},
    {"name": "Ryanair", "total": 28, "tp": 15, "tn": 13, "fp": 0, "fn": 0},
    {"name": "Crunchyroll", "total": 53, "tp": 33, "tn": 17, "fp": 0, "fn": 3},
    {"name": "Mapy", "total": 52, "tp": 12, "tn": 32, "fp": 0, "fn": 8},
    {"name": "LidlPlus", "total": 73, "tp": 47, "tn": 25, "fp": 0, "fn": 1},
    {"name": "Klarna", "total": 40, "tp": 15, "tn": 21, "fp": 4, "fn": 0},
    {"name": "JustEat", "total": 40, "tp": 16, "tn": 7, "fp": 10, "fn": 7},
    {"name": "Glovo", "total": 40, "tp": 14, "tn": 26, "fp": 0, "fn": 0},
    {"name": "Alza", "total": 91, "tp": 61, "tn": 40, "fp": 0, "fn": 0},
    {"name": "Vinted", "total": 114, "tp": 58, "tn": 54, "fp": 0, "fn": 2},
    {"name": "Expedia", "total": 1332, "tp": 1149, "tn": 173, "fp": 2, "fn": 8},
    {"name": "Hostelworld", "total": 208, "tp": 108, "tn": 99, "fp": 0, "fn": 1},
    {"name": "Austrian", "total": 247, "tp": 103, "tn": 131, "fp": 13, "fn": 0},
    {"name": "Warframe", "total": 248, "tp": 71, "tn": 15, "fp": 162, "fn": 0},
    {"name": "AviraVPN", "total": 90, "tp": 55, "tn": 35, "fp": 0, "fn": 0},
    {"name": "FireNetVPN", "total": 95, "tp": 75, "tn": 20, "fp": 0, "fn": 0},
    {"name": "HideVPN", "total": 48, "tp": 6, "tn": 42, "fp": 0, "fn": 0},
    {"name": "HoxxVPN", "total": 186, "tp": 5, "tn": 181, "fp": 0, "fn": 0},
    {"name": "PlanetVPN", "total": 290, "tp": 231, "tn": 59, "fp": 0, "fn": 0},
    {"name": "UltrasurfVPN", "total": 90, "tp": 49, "tn": 41, "fp": 0, "fn": 0},
    {"name": "XrpTunnelVPN", "total": 30, "tp": 19, "tn": 11, "fp": 0, "fn": 0},
    {"name": "NotebookLLM", "total": 19, "tp": 10, "tn": 9, "fp": 0, "fn": 0},
    {"name": "Maps", "total": 69, "tp": 54, "tn": 15, "fp": 0, "fn": 0},
    {"name": "MapsOffline", "total": 62, "tp": 43, "tn": 19, "fp": 0, "fn": 0},
]

applications_data_nDPI = [
    {"name": "Doctor_App", "total": 36, "tp": 18, "tn": 18, "fp": 0, "fn": 0},
    {"name": "Trenitalia", "total": 33, "tp": 16, "tn": 17, "fp": 0, "fn": 0},
    {"name": "Subito", "total": 59, "tp": 31, "tn": 28, "fp": 0, "fn": 0},
    {"name": "Strava", "total": 95, "tp": 68, "tn": 27, "fp": 0, "fn": 0},
    {"name": "Notion", "total": 54, "tp": 30, "tn": 19, "fp": 0, "fn": 5},
    {"name": "MarioKart", "total": 52, "tp": 48, "tn": 4, "fp": 0, "fn": 0},
    {"name": "MarinoBus", "total": 19, "tp": 7, "tn": 12, "fp": 0, "fn": 0},
    {"name": "Ryanair", "total": 28, "tp": 15, "tn": 13, "fp": 0, "fn": 0},
    {"name": "Crunchyroll", "total": 53, "tp": 29, "tn": 17, "fp": 0, "fn": 7},
    {"name": "Mapy", "total": 52, "tp": 12, "tn": 32, "fp": 0, "fn": 8},
    {"name": "LidlPlus", "total": 73, "tp": 42, "tn": 20, "fp": 5, "fn": 6},
    {"name": "Klarna", "total": 40, "tp": 15, "tn": 21, "fp": 4, "fn": 0},
    {"name": "JustEat", "total": 40, "tp": 16, "tn": 7, "fp": 10, "fn": 7},
    {"name": "Glovo", "total": 40, "tp": 14, "tn": 26, "fp": 0, "fn": 0},
    {"name": "Alza", "total": 91, "tp": 61, "tn": 40, "fp": 0, "fn": 0},
    {"name": "Vinted", "total": 114, "tp": 52, "tn": 54, "fp": 0, "fn": 8},
    {"name": "Expedia", "total": 1332, "tp": 1031, "tn": 173, "fp": 2, "fn": 126},
    {"name": "Hostelworld", "total": 208, "tp": 108, "tn": 99, "fp": 0, "fn": 1},
    {"name": "Austrian", "total": 247, "tp": 103, "tn": 131, "fp": 13, "fn": 0},
    {"name": "Warframe", "total": 248, "tp": 71, "tn": 20, "fp": 157, "fn": 0},
    {"name": "AviraVPN", "total": 90, "tp": 55, "tn": 35, "fp": 0, "fn": 0},
    {"name": "FireNetVPN", "total": 95, "tp": 72, "tn": 20, "fp": 0, "fn": 3},
    {"name": "HideVPN", "total": 48, "tp": 6, "tn": 42, "fp": 0, "fn": 0},
    {"name": "HoxxVPN", "total": 186, "tp": 5, "tn": 181, "fp": 0, "fn": 0},
    {"name": "PlanetVPN", "total": 290, "tp": 231, "tn": 59, "fp": 0, "fn": 0},
    {"name": "UltrasurfVPN", "total": 90, "tp": 49, "tn": 41, "fp": 0, "fn": 0},
    {"name": "XrpTunnelVPN", "total": 30, "tp": 19, "tn": 11, "fp": 0, "fn": 0},
    {"name": "NotebookLLM", "total": 19, "tp": 10, "tn": 9, "fp": 0, "fn": 0},
    {"name": "Maps", "total": 69, "tp": 54, "tn": 15, "fp": 0, "fn": 0},
    {"name": "MapsOffline", "total": 62, "tp": 43, "tn": 19, "fp": 0, "fn": 0},
]

applications_data_20 = [
    {"name": "Doctor_App", "total": 36, "tp": 18, "tn": 18, "fp": 0, "fn": 0},
    {"name": "Trenitalia", "total": 33, "tp": 16, "tn": 17, "fp": 0, "fn": 0},
    {"name": "Subito", "total": 59, "tp": 31, "tn": 28, "fp": 0, "fn": 0},
    {"name": "Strava", "total": 95, "tp": 68, "tn": 27, "fp": 0, "fn": 0},
    {"name": "Notion", "total": 54, "tp": 30, "tn": 19, "fp": 0, "fn": 5},
    {"name": "MarioKart", "total": 52, "tp": 48, "tn": 4, "fp": 0, "fn": 0},
    {"name": "MarinoBus", "total": 19, "tp": 7, "tn": 12, "fp": 0, "fn": 0},
    {"name": "Ryanair", "total": 28, "tp": 14, "tn": 13, "fp": 0, "fn": 1},
    {"name": "Crunchyroll", "total": 53, "tp": 18, "tn": 17, "fp": 0, "fn": 18},
    {"name": "Mapy", "total": 52, "tp": 7, "tn": 32, "fp": 0, "fn": 13},
    {"name": "LidlPlus", "total": 73, "tp": 29, "tn": 25, "fp": 0, "fn": 19},
    {"name": "Klarna", "total": 40, "tp": 15, "tn": 21, "fp": 4, "fn": 0},
    {"name": "JustEat", "total": 40, "tp": 11, "tn": 19, "fp": 5, "fn": 5},
    {"name": "Glovo", "total": 40, "tp": 12, "tn": 26, "fp": 0, "fn": 2},
    {"name": "Alza", "total": 91, "tp": 61, "tn": 40, "fp": 0, "fn": 0},
    {"name": "Vinted", "total": 114, "tp": 52, "tn": 54, "fp": 0, "fn": 8},
    {"name": "Expedia", "total": 1332, "tp": 1145, "tn": 175, "fp": 0, "fn": 12},
    {"name": "Hostelworld", "total": 208, "tp": 108, "tn": 99, "fp": 0, "fn": 1},
    {"name": "Austrian", "total": 247, "tp": 103, "tn": 121, "fp": 23, "fn": 0},
    {"name": "Warframe", "total": 248, "tp": 63, "tn": 15, "fp": 0, "fn": 170},
    {"name": "AviraVPN", "total": 90, "tp": 55, "tn": 35, "fp": 0, "fn": 0},
    {"name": "FireNetVPN", "total": 95, "tp": 75, "tn": 20, "fp": 0, "fn": 0},
    {"name": "HideVPN", "total": 48, "tp": 6, "tn": 42, "fp": 0, "fn": 0},
    {"name": "HoxxVPN", "total": 186, "tp": 5, "tn": 181, "fp": 0, "fn": 0},
    {"name": "PlanetVPN", "total": 290, "tp": 231, "tn": 59, "fp": 0, "fn": 0},
    {"name": "UltrasurfVPN", "total": 90, "tp": 49, "tn": 41, "fp": 0, "fn": 0},
    {"name": "XrpTunnelVPN", "total": 30, "tp": 17, "tn": 11, "fp": 0, "fn": 2},
    {"name": "NotebookLLM", "total": 19, "tp": 10, "tn": 9, "fp": 0, "fn": 0},
    {"name": "Maps", "total": 69, "tp": 54, "tn": 15, "fp": 0, "fn": 0},
    {"name": "MapsOffline", "total": 62, "tp": 43, "tn": 19, "fp": 0, "fn": 0},
]

def aggregate_confusion(applications_data):
    TP = sum(app["tp"] for app in applications_data)
    TN = sum(app["tn"] for app in applications_data)
    FP = sum(app["fp"] for app in applications_data)
    FN = sum(app["fn"] for app in applications_data)
    return TP, TN, FP, FN


def plot_confusion_matrix(applications_data, output_file="validation_results/caseC/confusion_matrix.png"):
    TP, TN, FP, FN = aggregate_confusion(applications_data)

    total = TP + TN + FP + FN
    if total == 0:
        total = 1  # evita divisione per zero

    # Calcoliamo le percentuali
    TPp = (TP / total) * 100
    TNp = (TN / total) * 100
    FPp = (FP / total) * 100
    FNp = (FN / total) * 100

    matrix = [[TPp, FPp],
              [FNp, TNp]]

    plt.figure(figsize=(6, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt=".1f",  # un decimale
        cmap="Blues",
        xticklabels=["Predicted Positive", "Predicted Negative"],
        yticklabels=["Actual Positive", "Actual Negative"]
    )
    plt.title("Aggregated Confusion Matrix (in %)")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved confusion matrix to {output_file}")


def plot_metrics(applications_data, output_file="validation_results/caseC/metrics.png"):
    TP, TN, FP, FN = aggregate_confusion(applications_data)

    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    metrics = {
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-score": f1
    }

    values = [v * 100 for v in metrics.values()]
    max_val = max(values) if values else 0

    plt.figure(figsize=(6, 4))
    plt.bar(metrics.keys(), values, color=["#1f77b4", "#2ca02c", "#d62728", "#ff7f0e"])
    plt.ylim(0, max_val + 10)
    for i, v in enumerate(values):
        plt.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontsize=10)
    plt.title("Aggregated Metrics")
    plt.ylabel("Percentage (%)")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved metrics plot to {output_file}")

def plot_and_save_coverage_graphs(name, stats, output_dir="validation_results/caseC"):
    # Crea la cartella se non esiste
    os.makedirs(output_dir, exist_ok=True)

    methods = ["ndpi", "gt", "system"]
    method_labels = ["nDPI only", "nDPI + GT", "nDPI + My System"]
    colors = [("#1f77b4", "#aec7e8"), ("#2ca02c", "#98df8a"), ("#d62728", "#ff9896")]

    apps = list(stats.keys())
    x = np.arange(len(apps))
    bar_width = 0.35

    for i, method in enumerate(methods):
        #packet_cov = []
        flow_cov = []

        for app in apps:
            app_data = stats.get(app, {}).get(method, {})
            #packet_cov.append(app_data.get("packet_coverage", 0))
            flow_cov.append(app_data.get("flow_coverage", 0))

        fig, ax = plt.subplots(figsize=(15, 6))
        #ax.bar(x - bar_width/2, packet_cov, bar_width, label="Packets (%)", color=colors[i][0])
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
        output_path = os.path.join(output_dir, f"coverage{name}_{method}.png")
        plt.savefig(output_path, dpi=300)
        plt.close(fig)

        print(f"[+] Saved: {output_path}")

def plot_combined_coverage(name, stats, output_dir="validation_results/caseC"):
    os.makedirs(output_dir, exist_ok=True)

    methods = ["ndpi", "gt", "system"]
    method_labels = ["nDPI only", "nDPI + GT", "nDPI + My System"]
    colors = ["#1f77b4", "#2ca02c", "#d62728"]  # blu, verde, rosso

    apps = list(stats.keys())
    x = np.arange(len(apps))
    bar_width = 0.14  # più stretto per lasciare spazio ai 3 gruppi
    alpha = 0.8

    fig, ax = plt.subplots(figsize=(18, 7))

    # Ogni metodo sarà affiancato
    for i, method in enumerate(methods):
        #packet_cov = []
        flow_cov = []

        for app in apps:
            app_data = stats.get(app, {}).get(method, {})
            #packet_cov.append(app_data.get("packet_coverage", 0))
            flow_cov.append(app_data.get("flow_coverage", 0))

        # offset per posizionare i gruppi affiancati
        offset = (i - 1) * (2 * bar_width + 0.02)

        # barre Packets e Flows per il metodo corrente
        #ax.bar(
        #    x + offset - bar_width / 2, packet_cov, bar_width,
        #    label=f"{method_labels[i]} – Packets", color=colors[i], alpha=alpha
        #)
        ax.bar(
            x + offset + bar_width / 2, flow_cov, bar_width,
            label=f"{method_labels[i]} – Flows", color=colors[i], alpha=alpha * 0.7
        )

    ax.set_xlabel("Applications")
    ax.set_ylabel("Coverage (%)")
    ax.set_title(f"Coverage Comparison – {name}")
    ax.set_xticks(x)
    ax.set_xticklabels(apps, rotation=45, ha="right", fontsize=9)
    ax.legend(fontsize=9, ncol=2)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()

    output_path = os.path.join(output_dir, f"coverage_{name}_combined.png")
    plt.savefig(output_path, dpi=300)
    plt.close(fig)

    print(f"[+] Saved combined coverage graph: {output_path}")

applications = [
    "Doctor_App", "Trenitalia", "Subito", "Strava", "Notion", "MarioKart", "MarinoBus", "Ryanair", "Crunchyroll",
    "Mapy",  "LidlPlus", "Klarna", "JustEat", "Glovo", "Alza", "Vinted"
]
applicationsSub = [
    "NotebookLLM", "Maps", "MapsOffline"
]
applicationsWeb = [
    "Expedia", "Hostelworld", "Austrian", "Warframe"
]
applicationsVPN = [
    "AviraVPN", "FireNetVPN", "HideVPN", "HoxxVPN", "PlanetVPN", "UltrasurfVPN", "XrpTunnelVPN"
]

#applications = ["FireNetVPN"]

def extract_coverage_stats(applications, base_dir="coverage"):

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

#stats = extract_coverage_stats(applications)
#plot_and_save_coverage_graphs("", stats)

stats = extract_coverage_stats(applications)
plot_and_save_coverage_graphs("Main", stats)
plot_combined_coverage("Main", stats)

stats = extract_coverage_stats(applicationsSub)
plot_and_save_coverage_graphs("Sub", stats)
plot_combined_coverage("Sub", stats)

stats = extract_coverage_stats(applicationsWeb)
plot_and_save_coverage_graphs("Web", stats)
plot_combined_coverage("Web", stats)

stats = extract_coverage_stats(applicationsVPN)
plot_and_save_coverage_graphs("VPN", stats)
plot_combined_coverage("VPN", stats)

plot_confusion_matrix(applications_data_20)
plot_metrics(applications_data_20)
