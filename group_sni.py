
def group_sni(cluster):
    
    # extract the SNI list from the cluster
    sni_list = cluster["sni_list"]

    # If the SNI list is empty, return the cluster as is
    if not sni_list:
        return cluster
    
    groups = []
    # get a sorted list of unique SNIs
    unique_sni = sorted(set(sni_list))

    while unique_sni:
        # take the first SNI as the base for comparison
        base = unique_sni.pop(0)
        base_parts = base.split(".")
        common = [base]
        remaining = []

        for sni in unique_sni:
            parts = sni.split(".")

            # find common suffix from the end
            i = 1
            while i <= min(len(base_parts), len(parts)) and base_parts[-i] == parts[-i]:
                i += 1
            common_suffix = ".".join(base_parts[-(i-1):]) if i > 1 else None

            # if at least domain + TLD are common
            if common_suffix and common_suffix.count(".") >= 1:
                common.append(sni)
            else:
                remaining.append(sni)

        # calculate effective base domain if more than one in common
        if len(common) > 1:
            common_parts = [c.split(".") for c in common]
            min_len = min(len(p) for p in common_parts)
            i = 1
            while i <= min_len and all(p[-i] == common_parts[0][-i] for p in common_parts):
                i += 1
            base_domain = ".".join(common_parts[0][-(i-1):])
            groups.append(base_domain)
        else:
            groups.append(base)

        # update the list with remaining SNIs
        unique_sni = remaining

    # update the cluster's sni_list with grouped SNIs
    cluster["sni_list"] = groups
    return cluster

def merge_clusters(clusters: list) -> list:

    # group SNIs within each cluster
    clusters = [group_sni(c) for c in clusters]

    # sort clusters by descending length of sni_list (IMPORTANT)
    clusters.sort(key=lambda c: len(c["sni_list"]), reverse=True)

    i = 0
    while i < len(clusters):
        large_cluster = clusters[i]
        j = i + 1
        while j < len(clusters):
            small_cluster = clusters[j]

            # try merging only if both clusters have SNIs
            if not large_cluster["sni_list"] or not small_cluster["sni_list"]:
                j += 1
                continue

            # combine the SNI lists from the large and small clusters
            union = {
                "sni_list": large_cluster["sni_list"] + small_cluster["sni_list"]
            }
            # group the combined SNI list
            grouped_union = group_sni(union)

            # if grouping reduces the total number of SNIs
            if len(grouped_union["sni_list"]) < (len(large_cluster["sni_list"]) + len(small_cluster["sni_list"])):
                reduced = set(grouped_union["sni_list"])
                #print(f"\n{reduced}\n\n{large_cluster['sni_list']}\n\n{small_cluster['sni_list']}\n\n")

                new_large = []
                for s in large_cluster["sni_list"]:
                    # check if each SNI in the large cluster has been reduced
                    matches = [r for r in reduced if s.endswith(r)]
                    if matches:
                        # replace with the reduced SNI
                        new_large.append(matches[0])
                    else:
                        # keep original SNI
                        new_large.append(s)
                large_cluster["sni_list"] = sorted(set(new_large))

                # remove from small cluster SNIs absorbed by the large cluster
                small_cluster["sni_list"] = [
                    s for s in small_cluster["sni_list"]
                    if not any(r in reduced and s.endswith(r) for r in reduced)
                ]

                # sum flow_count and packets from small to large cluster
                large_cluster["flow_count"] += small_cluster.get("flow_count", 0)
                large_cluster["packets"] += small_cluster.get("packets", 0)
                small_cluster["flow_count"] = 0
                small_cluster["packets"] = 0

            j += 1
        i += 1

    # remove empty clusters
    clusters = [c for c in clusters if c["sni_list"]]
    return clusters
