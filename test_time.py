import json
import sys
from datetime import datetime

def estrai_attributi(file_input):
    with open(file_input, "r") as f:
        for riga in f:
            try:
                dato = json.loads(riga.strip())

                first_seen = dato.get("first_seen")
                last_seen = dato.get("last_seen")
                duration = dato.get("duration")

                # Conversione timestamp -> orario umano (ISO 8601)
                first_seen_h = datetime.fromtimestamp(first_seen).isoformat(sep=" ", timespec="milliseconds") if first_seen else None
                last_seen_h = datetime.fromtimestamp(last_seen).isoformat(sep=" ", timespec="milliseconds") if last_seen else None

                risultato = {
                    "first_seen": first_seen_h,
                    "last_seen": last_seen_h,
                    "duration": duration
                }
                print(risultato)
            except json.JSONDecodeError:
                print("Errore nel parsing della riga:", riga.strip(), file=sys.stderr)

if __name__ == "__main__":
    # esempio: python script.py flussi.json
    if len(sys.argv) < 2:
        print("Uso: python script.py <file_input>")
    else:
        estrai_attributi(sys.argv[1])
