from llama_cpp import Llama

llm = Llama(model_path="path_al_modello/ggml-model-q4_0.bin")

domains = ["app.lefrecce.it", "dpm.demdex.net", "fstechnologyspa.data.adobedc.net"]
prompt = f"Dimmi solo i nomi dei processi che generano questi domini: {', '.join(domains)}"

response = llm(prompt, max_tokens=50)
print(response['choices'][0]['text'])