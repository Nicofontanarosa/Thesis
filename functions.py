

from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
# -------------------------------------------
import config

# protocols to keep
protocols = config.PROTOCOLS

# -------------------------------------------

def protocols_summary(flows):

    protocol_cou = Counter()

    for flow in flows:
        proto = flow.get("proto_field", "").lower()

        # search for known protocols
        matched = False
        for p in protocols:
            if p.lower() in proto:
                protocol_cou[p] += 1
                matched = True
                break

        # if no known protocol matched, count as Unknown
        # 1 flow will be counted as Unknown for sure
        if not matched:
            protocol_cou["Unknown"] += 1

    return protocol_cou

# -------------------------------------------

# Vector Space Similarity Search using TF-IDF Term Frequency Inverse Document Frequency -> transform SNI in number vector
# Cosine Similarity -> similarity of flows
# Thresholding of flows
# Clustering with modified K-Means -> 1 group
def clustering(final_flows, word):

    # Cosine similarity threshold
    # 0.1 = flows with similarity >= 10% are considered relevant
    threshold = config.THRESHOLD
    n_min = config.N_MIN
    n_max = config.N_MAX

    # Extract all SNIs from the flows
    sni_list = [str(flow.get("sni", "")).lower() for flow in final_flows]

    # TF-IDF on character n-grams of length 2 and 3
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(n_min,n_max))
    # TF-IDF matrix for all SNIs in the list
    # Each row represents an SNI and each column an n-gram
    X = vectorizer.fit_transform(sni_list)
    # TF-IDF vector of the target word
    word_vec = vectorizer.transform([word])
    # Cosine similarity between the target word and all SNIs
    sims = cosine_similarity(word_vec, X).flatten()
    
    # Select flows above the threshold
    # zip pairs each flow with its similarity value
    cluster_flows = [flow for flow, sim in zip(final_flows, sims) if sim >= threshold]
    
    return {word: cluster_flows}

# -------------------------------------------

def search_flows(final_flows):
    
    while True:
        print_flows(final_flows)

        word = input("\nSearch: ").strip()
        if not word:
            continue
        else:
            cluster = clustering(final_flows, word)

        print_flows(cluster[word])
        print_rules(cluster[word], word)

        choice = input("\nPress ENTER to continue or type 'exit' to quit: ").strip().lower()
        if choice == "exit":
            break

# -------------------------------------------

def print_flows(final_flows):

    # Clear del terminale all'apertura
    config.clear_terminal()

    protocol_counts = protocols_summary(final_flows)

    # printing summary
    summary = ", ".join([f"{v} flows {k}" for k, v in protocol_counts.items()])
    print(f"\nDetected: {summary}")

    # --- DNS FLOWS PRINT ---
    print("\nDNS flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "dns" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

    # --- HTTP FLOWS PRINT ---
    print("\nHTTP flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "http" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

    # --- TLS FLOWS PRINT ---
    print("\nTLS flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "tls" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

    # --- QUIC FLOWS PRINT ---
    print("\nQUIC flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "quic" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

    # --- SMTP FLOWS PRINT ---
    print("\nSMTP flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "smtp" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

    # --- UNKNOWN FLOWS PRINT ---
    print("\nUnknown flows detected:\n")
    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if "unknown" in proto:
            for k, v in flow.items():
                print(f"  ├── {k}: {v}")
            print("\n")

# -------------------------------------------

def print_rules(flows, protocol_name):

    # Set to keep unique SNI values
    sni_set = set()

    for flow in flows:
        sni = flow.get("sni", "")
        if sni:
            sni_set.add(sni.lower())

    # No SNI found
    if not sni_set:
        return None

    # Build nDPI rule
    host_entries = ",".join([f'host:"{sni}"' for sni in sorted(sni_set)])
    rule = f"{host_entries}@{protocol_name.capitalize()}"

    print(rule)

# -------------------------------------------
