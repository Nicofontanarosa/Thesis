document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = document.getElementById("pcap").files[0];
  if(!f) return alert("Seleziona un file .pcap");

  const form = new FormData();
  form.append("pcap", f, f.name);

  document.getElementById("output").textContent = "Uploading...";
  try {
    const res = await fetch("/analyze", { method: "POST", body: form });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || res.statusText);
    }
    const data = await res.json();
    document.getElementById("output").textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    document.getElementById("output").textContent = "Errore: " + err.message;
  }
});
