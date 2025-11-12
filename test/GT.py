
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

GT = {
    "DoctorApp": {"sni": ["doctorapp.it"], "ja4": [""], "cert": [""]},
    "Trenitalia": {"sni": ["app.lefrecce.it"], "ja4": [""], "cert": [""]},
    "Subito": {"sni": ["sbito.it", "subito.it"], "ja4": [""], "cert": [""]},
    "Strava": {"sni": ["strava.com"], "ja4": [""], "cert": [""]},
    "Notion": {"sni": ["notion.so", "notionusercontent.com"], "ja4": [""], "cert": [""]},
    "NotebookLLM": {"sni": ["notebooklm-pa.googleapis.com"], "ja4": [""], "cert": [""]},
    "MarioKart": {"sni": ["mariokarttour.com"], "ja4": [""], "cert": [""]},
    "MarinoBus": {"sni": ["marinobus.it"], "ja4": [""], "cert": [""]},
    "Mapy": {"sni": ["mapy.cz"], "ja4": [""], "cert": [""]},
    "Maps": {"sni": ["mobilemaps.googleapis.com"], "ja4": [""], "cert": [""]},
    "MapsOffline": {"sni": ["offline-maps.gvt1.com"], "ja4": [""], "cert": [""]},
    "LidlPlus": {"sni": ["lidl.it", "lidlplus.com", "leaflets.schwarz", "lidl.com"], "ja4": [""], "cert": [""]},
    "Klarna": {"sni": ["klarna.com"], "ja4": [""], "cert": [""]},
    "JustEat": {"sni": ["just-eat.io", "justeattakeaway.com", "justeat-int.com", "justeat.it"], "ja4": [""], "cert": [""]},
    "Glovo": {"sni": ["glovo.dhmedia.io", "glovoapp.com"], "ja4": [""], "cert": [""]},
    "Alza": {"sni": ["alza.cz"], "ja4": [""], "cert": [""]},
    "Vinted": {"sni": ["vinted.fr", "vinted.com", "vinted.net", "vintedapp.com"], "ja4": [""], "cert": [""]},
    "Ryanair": {"sni": ["ryanair.com"], "ja4": [""], "cert": [""]},
    "Crunchyroll": {"sni": ["crunchyroll.com", "vrv.co"], "ja4": [""], "cert": [""]},
    "Expedia": {"sni": ["expedia.com", "travel-assets.com"], "ja4": [""], "cert": [""]},
    "HostelWorld": {"sni": ["hwstatic.com", "hostelworld.com"], "ja4": [""], "cert": [""]},
    "Austrian": {"sni": ["austrian.com", "austrian.miles-and-more.com"], "ja4": [""], "cert": [""]},
    "Warframe": {"sni": ["warframe.market"], "ja4": [""], "cert": [""]},
    "AviraVPN": {"sni": ["avira-vpn.com"], "ja4": [""], "cert": [""]},
    "FireVPN": {"sni": ["ptisupporterteam.xyz"], "ja4": [""], "cert": [""]},
    "HideVPN": {"sni": ["hide.me"], "ja4": ["t13d1511h2_8daaf6152771_40271e0a5736"], "cert": [""]},
    "HoxxVPN": {"sni": ["hoxx.com"], "ja4": [""], "cert": [""]},
    "PlanetVPN": {"sni": ["fuck.rkn"], "ja4": [""], "cert": [""]},
    "UltraSurfVPN": {"sni": [""], "ja4": ["t13d1913h2_9dc949149365_6e36e74388e1"], "cert": [""]},
    "XrpTunnelVPN": {"sni": ["aliavpn.xyz", "portal.seafy.com"], "ja4": [""], "cert": [""]}
}

# --- Costruisci i dati per il DataFrame ---
data = {}
for app, vals in GT.items():
    # scegli SNI > cert > JA4
    combined = []
    if any(s for s in vals["sni"] if s != ""):
        combined = [s for s in vals["sni"] if s != ""]
    elif any(c for c in vals["cert"] if c != ""):
        combined = [c for c in vals["cert"] if c != ""]
    elif any(j for j in vals["ja4"] if j != ""):
        combined = [j for j in vals["ja4"] if j != ""]
    else:
        combined = ["-"]

    data[app] = {
        "SNI/JA4/CN": "\n".join(combined)
    }

# Crea DataFrame
df = pd.DataFrame.from_dict(data, orient="index")

# Dividiamo le applicazioni in due metà
mid = (len(df) + 1) // 2
df_left = df.iloc[:mid]
df_right = df.iloc[mid:]

# Figura larga per due tabelle affiancate
fig, ax = plt.subplots(figsize=(20, max(10, mid*0.7)))
ax.axis("off")

# Tabella sinistra
tbl_left = ax.table(cellText=df_left.values,
                    rowLabels=df_left.index,
                    colLabels=df_left.columns,
                    cellLoc='center',
                    rowLoc='center',
                    loc='upper left')

# Tabella destra
tbl_right = ax.table(cellText=df_right.values,
                     rowLabels=df_right.index,
                     colLabels=df_right.columns,
                     cellLoc='center',
                     rowLoc='center',
                     loc='upper right')

# Imposta altezza righe, larghezza colonne ridotte e testo in grassetto
for tbl in [tbl_left, tbl_right]:
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    for key, cell in tbl.get_celld().items():
        cell.set_height(0.09)
        cell.set_width(0.25)
        cell.get_text().set_multialignment('center')
        cell.get_text().set_wrap(True)
        cell.get_text().set_fontweight('bold')  # testo in grassetto
        cell.set_edgecolor("black")             # colore bordo
        cell.set_linewidth(1.5)                    # spessore bordo

plt.tight_layout()
plt.savefig("GT_SNI_JA4_CN_matrix.png")
plt.show()
