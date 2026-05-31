import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from modul_vulnerability import get_vuln_context
from modul_threat import get_threat_context, get_malware_context
from modul_logs import search_logs

print("USE CASE 1: Threat Intelligence & Vulnerability Analysis")

print("\n[1a] Threat Actor Profiling (APT28)")
print(get_threat_context("APT28"))

print("\n[1b] Malware Investigation (WannaCry)")
print(get_malware_context("WannaCry"))

print("\n[1c] Vulnerability Relationship Analysis (CVE-2017-0144)")
print(get_vuln_context("CVE-2017-0144"))

print("USE CASE 2: Security Log Analysis")

print("\n[2a] Deteksi aktivitas brute force")
print(search_logs("failed password login attempt"))

print("\n[2b] Deteksi reverse shell")
print(search_logs("reverse shell suspicious connection port 4444"))

print("\n[2c] Deteksi privilege escalation")
print(search_logs("sudo privilege escalation unauthorized"))

print("USE CASE 3: Log Analysis + Global Threat Intelligence")

print("\n[3] Korelasi log mencurigakan dengan threat intelligence")
log_result = search_logs("malware detected suspicious file")
vuln_result = get_vuln_context("CVE-2017-0144")
threat_result = get_malware_context("WannaCry")

print("Log yang ditemukan")
print(log_result)
print("Threat Intelligence terkait")
print(threat_result)
print("Vulnerability terkait")
print(vuln_result)