import ssl
from pathlib import Path
import requests

ssl._create_default_https_context = ssl._create_unverified_context

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parents[1] / "data" / "enterprise-attack.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

print("Downloading MITRE ATT&CK data... (mungkin 1-2 menit)")
response = requests.get(URL, verify=False)
response.raise_for_status()

OUT.write_text(response.text, encoding="utf-8")
print(f"Selesai! File enterprise-attack.json sudah tersimpan di: {OUT}")