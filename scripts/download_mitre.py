import requests
import json

print("Downloading MITRE ATT&CK data... (mungkin 1-2 menit)")
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
response = requests.get(url, verify=False)

with open("enterprise-attack.json", "w", encoding="utf-8") as f:
    f.write(response.text)

print("Selesai! File enterprise-attack.json sudah tersimpan.")