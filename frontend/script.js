const form = document.getElementById("pcapForm");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = document.getElementById("pcapFile").files[0];
  const formData = new FormData();
  formData.append("pcap", file);

  const res = await fetch("/upload", {
    method: "POST",
    body: formData
  });
  
  const text = await res.text();
  document.getElementById("output").textContent = text;
});
