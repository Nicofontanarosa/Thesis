
# nDPI/example/ndpiReader -v 2 -i tesi/input.pcapng > tesi/output.json

# /home/keiyukensei/nDPI/src/include/ndpi_protocol_ids.h
# /home/keiyukensei/nDPI/src/lib/ndpi_content_match.c.inc
# nDPI/src/include/ndpi_typedefs.h

import os
import argparse

# variabili globali
PROTOCOLS = {"DNS", "TLS", "HTTP", "QUIC", "Unknown", "SMTP"}

def clear_terminal():
    # pulizia terminale
    os.system('cls' if os.name == 'nt' else 'clear')

def get_args():
    # creazione parser per argomenti da linea di comando
    parser = argparse.ArgumentParser(description="Estrazione flussi da output nDPI")
    parser.add_argument("input_file", help="File di input con i flussi nDPI")
    parser.add_argument("-o", "--output", default="output_flussi.json", help="File JSON di output (default: output_flussi.json)")
    return parser.parse_args()

def print_files(input_file, output_file):
    # stampa file usati
    print(f"\nFile di input: {input_file}")
    print(f"File di output: {output_file}\n")