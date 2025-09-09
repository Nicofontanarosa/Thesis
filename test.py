import ollama

def classify_domain(domain):

    # Define the model and the input prompt
    prompt = f"You are a traffic monitoring assistant. Tell me in ONE WORD the name of the service / application to which this domain belongs: {domain}"

    # Send the query to the model
    response = client.generate(model="deepseek-r1", prompt=prompt)
    print(response.response)

# Initialize the Ollama client
client = ollama.Client()

# Initialize domains
domains = ["app.lefrecce.it", "dpm.demdex.net", "fstechnologyspa.data.adobedc.net"]
domains1 = ["api-sdk.datadome.co", "apps.rokt.com", "socket.vinted.net", "vintedapp.com", "www.vinted.fr", "images1.vinted.net", "init-mp.fyber.com", "logs-ingress.svc.vinted.com", "mobile-api.rokt.com", "mobile-data.onetrust.io", "sdk.fra-01.braze.eu"]
domains2 = ["op-de.storage.googleapis.com","or-se.storage.googleapis.com","os-de.storage.googleapis.com","rr1---sn-hpa7zn6s.offline-maps.gvt1.com", "rr1---sn-uv2pm-ugol.offline-maps.gvt1.com", "storage.googleapis.com", "offline-maps.gvt1.com","rr2---sn-uv2pm-ugol.offline-maps.gvt1.com","android.googleapis.com", "feedback-pa.googleapis.com","gz0.googleusercontent.com", "lh3.googleusercontent.com", "mobilemaps-pa-gz.googleapis.com"]

for d in domains2:
    classify_domain(d)

