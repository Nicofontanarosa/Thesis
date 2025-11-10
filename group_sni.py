
#################################################################
# File: group_sni.py to merge groups based on SNI similarity
#################################################################

def group_sni(group):
    
    group["sni_list_removed"] = []

    # extract the SNI list from the group
    sni_list = group["sni_list"]

    # If the SNI list is empty, return the group as is
    if not sni_list:
        return group
    
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

            # add removed SNIs aggregated (except the base_domain) to the removed list
            for s in common:
                if s != base_domain:
                    group["sni_list_removed"].append(s)
        else:
            groups.append(base)

        # update the list with remaining SNIs
        unique_sni = remaining

    # update the group's sni_list with grouped SNIs
    group["sni_list"] = groups
    return group

def merge_flows(groups: list) -> list:

    # group SNIs within each group
    groups = [group_sni(c) for c in groups]

    # --- Remove groups that have no SNI, no JA4, and no certificate ---
    def has_useful_data(group):
        if group.get('sni_list'):
            #print(f"\nsni_list: {group.get("sni_list")}\n")
            return True
        if group.get('ja4'):
            return True
        raw_cert = group.get('certificate', [])
        #print(f"\n[DEBUG] 2 raw_cert: {raw_cert}\n")
        certificate = {item[0]: item[1] for item in raw_cert if len(item) == 2}
        #print(f"\n\nCERT: {certificate.get('subject')}\n\n")
        if certificate.get('subject'):
            return True
        return False

    groups = [c for c in groups if has_useful_data(c)]
    #print(f"\n[DEBUG] Merged Group after group: {groups}")
    
    return groups

#################################################################
# End of group_sni.py
#################################################################