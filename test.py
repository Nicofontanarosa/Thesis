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
