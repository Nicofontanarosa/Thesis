import os
import uuid
import shutil
import subprocess
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
# Permetti il frontend (in produzione specifica solo il dominio)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "/tmp/pcaps"
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_SIZE_BYTES = 80 * 1024 * 1024  # 80MB, regola a piacere

def save_upload(upload_file: UploadFile, dest_path: str):
    with open(dest_path, "wb") as f:
        shutil.copyfileobj(upload_file.file, f)

@app.post("/analyze")
async def analyze(pcap: UploadFile = File(...)):
    # Controllo dimensione (se inviata Content-Length, altrimenti potresti aggiungere stream)
    if pcap.spool_max_size and pcap.spool_max_size > MAX_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File troppo grande")

    jobid = str(uuid.uuid4())
    tmp = os.path.join(UPLOAD_DIR, f"{jobid}.pcap")
    try:
        save_upload(pcap, tmp)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

    try:
        # Esegui lo script che invoca ndpi (vedi process_ndpi.sh)
        proc = subprocess.run(["/app/process_ndpi.sh", tmp],
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise Exception(proc.stderr or "ndpi failed")
        # Assumiamo output JSON o testo semplice
        return {"job": jobid, "output": proc.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Analisi troppo lunga (timeout)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(tmp)
        except:
            pass

# opzionale: serve frontend statico
from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory="/app/frontend", html=True), name="static")
