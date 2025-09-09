import ollama

def classify_domain(domain):

    # Define the model and the input prompt
    prompt = f"You are a traffic monitoring assistant. Tell me the name in ONE WORD of the parent company / service / application to which this domain belongs: {domain}"

    # Send the query to the model
    response = client.generate(model="gemma3", prompt=prompt)
    print(response.response)

# Initialize the Ollama client
client = ollama.Client()

# Initialize domains
domains = ["app.lefrecce.it", "dpm.demdex.net", "fstechnologyspa.data.adobedc.net"]

for d in domains:
    classify_domain(d)

├── api-sdk.datadome.co
  ├── apps.rokt.com
  ├── cdn.cookielaw.org
  ├── cdn2.inner-active.mobi
  ├── images1.vinted.net
  ├── init-mp.fyber.com
  ├── logs-ingress.svc.vinted.com
  ├── mobile-api.rokt.com
  ├── mobile-data.onetrust.io
  ├── sdk.fra-01.braze.eu
  ├── socket.vinted.net
  ├── vintedapp.com
  ├── www.vinted.fr

  ├── op-de.storage.googleapis.com
  ├── or-se.storage.googleapis.com
  ├── os-de.storage.googleapis.com
  ├── rr1---sn-hpa7zn6s.offline-maps.gvt1.com
  ├── rr1---sn-uv2pm-ugol.offline-maps.gvt1.com
  ├── rr2---sn-uv2pm-ugol.offline-maps.gvt1.com
  ├── android.googleapis.com
  ├── feedback-pa.googleapis.com
  ├── gz0.googleusercontent.com
  ├── lh3.googleusercontent.com
  ├── mobilemaps-pa-gz.googleapis.com
  ├── offline-maps.gvt1.com
  ├── storage.googleapis.com
  ├── www.google.com
  ├── www.googleapis.com
  ├── www.gstatic.com


