#!/usr/bin/env bash
set -euo pipefail
PCAP="$1"
# Percorso del binario ndpiReader - se nel Dockerfile lo installeremo in /usr/local/bin
NDPI_BIN="/usr/local/bin/ndpiReader"

if [ ! -x "$NDPI_BIN" ]; then
  echo "ndpiReader non trovato" >&2
  exit 2
fi

# Esempio di chiamata: qui dipende dal tuo uso di ndpiReader
# Semplice: invoca ndpiReader sul pcap e stampa l'output su stdout
"$NDPI_BIN" "$PCAP"
