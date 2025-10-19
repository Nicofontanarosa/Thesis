# Extracting Metadata from Encrypted Network Traffic to Generate nDPI Detection Rules — Master’s Thesis

### Overview

This repository contains the code and research developed for my **<mark>Master’s Thesis</mark>**. The goal is to extract meaningful metadata from encrypted network traffic ( *TLS, VPN etc ...* ) and use it to automatically generate detection rules for nDPI. The approach combines handshake analysis, TCP/TLS fingerprinting, and flow correlation to identify unknown or unclassified protocols.

![Static Badge](https://img.shields.io/badge/python-%20%3E%203.12-green?style=flat\&labelColor=red\&color=greed)
<a href="https://www.wireshark.org/"><img src="https://img.shields.io/badge/Wireshark-%20%3E%204.4-%234285F4?labelColor=blue)"></a>
![Static Badge](https://img.shields.io/badge/license-MIT-blue)
<a href="https://www.maxmind.com/en/geoip-databases"><img src="\[https://img.shields.io/github/v/release/xnbox/DeepfakeHTTP?style=flat-square\&color=28A745](https://img.shields.io/badge/MaxMind-Database-%237DCDA3?labelColor=%23FFA200)"></a>
<a href="https://github.com/Nicofontanarosa"><img src="https://img.shields.io/badge/powered\_by-Nicofontanarosa-blueviolet"></a>

---

# 🤸 Quickstart

To get started with **nDPI Protocol Generator**, follow these steps:

## 1️⃣ Install nDPI

Before running this tool, make sure **nDPI** is installed and compiled on your system. You can follow the official instructions from the [nDPI GitHub repository](https://github.com/ntop/nDPI). Once nDPI is installed, you can use this tool for metadata extraction and rule generation

## 2️⃣ Run the Tool

There are two ways to use this project:

1. 🖥️ Graphical interface ( *recommended* )
2. 💻 Command-line mode

###🖥️ Graphical Interface ( Textual-based UI )

- Install the textual library with `pip install textual`
- Then start the graphical interface with `python3 flow_viewer_textual.py`

In this version, the interface will ask for all required paths ( **PCAP file, nDPI root path, and output directory** ) through the GUI. ==!! you don’t need to type them in the terminal !!==

### 💻 Command-Line Mode

- If you prefer the command line, run: `python3 debug.py <pcap_path> <ndpi_path> <output_folder>`

***Example:***

`python3 debug.py /downloads/application.pcapng /home/Nico/nDPI/ test/application`

- Parameters:

1. **<pcap_path>** → path to your `.pcap` or `.pcapng` file (e.g., /downloads/app.pcapng)
2. **<ndpi_path>** → main `directory` where nDPI is installed (e.g., /home/Nico/nDPI/)
3. **<output_folder>** → directory where analysis results and generated rules will be saved (e.g., test/app/)

---

# 3️⃣ ⚙️ How it works?

After running the tool, you’ll find:

Extracted metadata from encrypted traffic (e.g., TLS handshakes, SNI, TCP options)

Automatically generated draft nDPI detection rules

Logs and statistics inside the output directory you specified

---

# 📌 Requirements

Python 3.10+

nDPI (installed and compiled)

(Optional) Textual → for the graphical interface

---

## 5️⃣ Next Steps

Once you have generated your rules, you can:

Test them directly with your nDPI installation

Integrate them into the ndpi proto file to extend protocol recognition

---

# 📄 License

This project is distributed under the terms of the MIT License. A complete copy of the license is available in the \[LICENSE](LICENSE) file within this repository. Any contribution made to this project will be licensed under the same MIT License

- Academic project developed for educational and research purposes in the field of cybersecurity
- Author: Nicolò Fontanarosa
- Email: nickcompanyofficial@gmail.com
- University: University of Pisa
- Year: 2025

## 🙌 DISCLAIMER

While I do my best to detect location anomalies, I cannot guarantee that this software is error-free or 100% accurate. Please ensure that you respect users' privacy and have proper authorization to monitor, capture, and inspect network traffic

!\[GitHub followers](https://img.shields.io/github/followers/Nicofontanarosa?style=social)





