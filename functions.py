

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

def print_flow(prot, final_flows):

    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if prot in proto:
            for k, v in flow.items():
                if "risk" in k.lower():  # se riguarda il rischio
                    print(f"  ├── \033[1;31m{k}: {v}\033[0m")  # rosso grassetto
                elif "sni" in k.lower() or "hostname" in k.lower():
                    print(f"  ├── \033[1;32m{k}: {v}\033[0m")  # verde grassetto
                else:
                    print(f"  ├── {k}: {v}")
            print("\n")

def print_flows(final_flows):

    protocol_counts = protocols_summary(final_flows)

    # printing summary
    summary = ", ".join([f"{v} flows {k}" for k, v in protocol_counts.items()])
    print(f"\nDetected: {summary}")

    # --- ALL SNIs SEEN (by levels) ---
    sni_list = [flow.get("sni") for flow in final_flows if "sni" in flow and flow["sni"]]
    unique_sni = sorted(set(sni_list))

    # Organized by levels
    levels = {}
    for sni in unique_sni:
        parts = sni.split(".")
        parts_rev = list(reversed(parts))
        for i in range(1, len(parts_rev) + 1):
            dom = ".".join(reversed(parts_rev[:i]))
            levels.setdefault(i, set()).add(dom)

    print("\nAll SNIs seen (by domain levels):")
    for level in sorted(levels.keys()):
        print(f"\n--- Level {level} ---")
        for dom in sorted(levels[level]):
            print(f"  ├── \033[1;32m{dom}\033[0m")

    # --- DNS FLOWS PRINT ---
    print("\nDNS flows detected:\n")
    print_flow("dns", final_flows)

    # --- HTTP FLOWS PRINT ---
    print("\nHTTP flows detected:\n")
    print_flow("http", final_flows)

    # --- TLS FLOWS PRINT ---
    print("\nTLS flows detected:\n")
    print_flow("tls", final_flows)

    # --- QUIC FLOWS PRINT ---
    print("\nQUIC flows detected:\n")
    print_flow("quic", final_flows)

    # --- SMTP FLOWS PRINT ---
    print("\nSMTP flows detected:\n")
    print_flow("smtp", final_flows)

    # --- UNKNOWN FLOWS PRINT ---
    print("\nUnknown flows detected:\n")
    print_flow("unknown", final_flows)

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

    print(f"\033[1m{rule}\033[0m")

# -------------------------------------------
