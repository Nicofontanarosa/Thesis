def print_flow(prot, final_flows):

    for flow in final_flows:
        proto = flow.get("proto_field", "").lower()
        if prot in proto:
            for k, v in flow.items():
                if "risk" in k.lower():
                    print(f"  ├── \033[1;31m{k}: {v}\033[0m")
                elif "sni" in k.lower() or "hostname" in k.lower():
                    print(f"  ├── \033[1;32m{k}: {v}\033[0m")
                else:
                    print(f"  ├── {k}: {v}")
            print("\n")


def print_flows(final_flows):

    # --- DNS FLOWS PRINT ---
    print("DNS flows detected:\n")
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