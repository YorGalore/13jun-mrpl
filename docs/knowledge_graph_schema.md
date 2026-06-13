# SEPSES CSKG Schema Report

> **PENTING — regenerasi sebelum dipakai sebagai bukti deliverable.**
> File ini ada dalam **format baru** `schema_inspector.py` terkini. Kolom hitung
> (`count`) dan bagian _Top Classes_/_Top Predicates_/_Sample Triples_ diisi
> otomatis ketika script dijalankan terhadap data nyata:
>
> ```bash
> # Sumber utama (data nyata, lengkap): endpoint SEPSES publik
> python scripts/generate_schema_report.py --target public
>
> # Atau dari Virtuoso lokal SETELAH data/cskg_dumps dimuat (docker compose up)
> python scripts/generate_schema_report.py --target local
> ```
>
> Versi lama file ini (mengandung `attack:Technique`, `vuln:Vulnerability`,
> kolom `samples`, "Graphs discovered", dan `Triples: 0`) dihasilkan terhadap
> Virtuoso lokal yang masih kosong dan **sudah tidak berlaku**.

- Endpoint: `https://sepses.ifs.tuwien.ac.at/sparql`
- Graph: `(default graph)`
- Triples: _(diisi saat run)_
- Distinct subjects: _(diisi saat run)_
- Distinct objects: _(diisi saat run)_

## Key Entity Classes (Issue #1)

Kelas inti SEPSES CSKG yang dipakai pipeline ini:

| class | label | catatan |
| --- | --- | --- |
| `cve:CVE` | CVE Vulnerability | Entry-point utama; di-query lewat literal `cve:id "CVE-YYYY-NNNN"`. |
| `cwe:Weakness` | CWE Weakness | Ditautkan dari CVE via `cve:hasCWE`. |
| `capec:AttackPattern` | CAPEC Attack Pattern | Ditautkan dari CWE via `cwe:hasCAPEC`. |
| `cpe:CPE` | CPE Platform | Produk/platform terdampak via `cve:hasCPE`. |
| `cvss:CVSS3BaseMetric` | CVSS v3 Base Metric | Skor via `cve:hasCVSS3BaseMetric` → `cvss:baseScore`. |
| `cvss:CVSS2BaseMetric` | CVSS v2 Base Metric | Fallback skor lama via `cve:hasCVSS2BaseMetric`. |

## Key Object Properties (relasi antar-entitas)

| predicate | arah | catatan |
| --- | --- | --- |
| `cve:hasCWE` | CVE → CWE | Rantai kerentanan. |
| `cve:hasCPE` | CVE → CPE | Produk terdampak. |
| `cve:hasCVSS3BaseMetric` | CVE → CVSS3 | Node metrik (skor di hop berikutnya). |
| `cve:hasCVSS2BaseMetric` | CVE → CVSS2 | Node metrik (skor di hop berikutnya). |
| `cwe:hasCAPEC` | CWE → CAPEC | Pola serangan terkait. |
| `cwe:hasCommonConsequence` | CWE → Consequence | Node konsekuensi (`cwe:consequenceImpact`). |
| `cwe:hasPotentialMitigation` | CWE → Mitigation | Mitigasi CWE (node → teks via hop berikutnya). |
| `capec:hasMitigation` | CAPEC → Mitigation | **Bukan** `capec:mitigation`. Node → teks via hop berikutnya. |
| `cvss:baseScore` | CVSS → skor | Nilai numerik base score. |

## Key Datatype Properties (atribut/teks)

| property | dipakai pada | catatan penting |
| --- | --- | --- |
| `cve:id` | CVE | Literal id (mis. `"CVE-2021-44228"`). |
| `cve:description` | CVE | Teks deskripsi CVE. |
| `dct:description` | **CWE & CAPEC** | Deskripsi CWE/CAPEC memakai **Dublin Core**, **bukan** `cwe:description` / `capec:description`. |
| `dct:issued` / `dct:modified` | CVE | Tanggal terbit/ubah (bukan `cve:publishedDate`). |
| `cwe:name` | CWE | Nama weakness. |
| `capec:name` | CAPEC | Nama attack pattern. |
| `cvss:baseScore` | CVSS metric | Skor numerik. |

## Top Classes

_(diisi saat run)_

## Top Predicates

_(diisi saat run)_

## Curated Security Classes

| class | label | count |
| --- | --- | --- |
| cve:CVE | CVE Vulnerability | _(run)_ |
| cwe:Weakness | CWE Weakness | _(run)_ |
| capec:AttackPattern | CAPEC Attack Pattern | _(run)_ |
| cpe:CPE | CPE Platform | _(run)_ |
| cvss:CVSS3BaseMetric | CVSS v3 Base Metric | _(run)_ |
| cvss:CVSS2BaseMetric | CVSS v2 Base Metric | _(run)_ |

## Curated Security Relations

| predicate | label | count |
| --- | --- | --- |
| cve:hasCWE | CVE -> CWE | _(run)_ |
| cve:hasCPE | CVE -> CPE | _(run)_ |
| cve:hasCVSS3BaseMetric | CVE -> CVSS3 | _(run)_ |
| cve:hasCVSS2BaseMetric | CVE -> CVSS2 | _(run)_ |
| cwe:hasCAPEC | CWE -> CAPEC | _(run)_ |
| cwe:hasCommonConsequence | CWE -> Consequence | _(run)_ |
| cwe:hasPotentialMitigation | CWE -> Mitigation | _(run)_ |
| capec:hasMitigation | CAPEC -> Mitigation | _(run)_ |
| cvss:baseScore | CVSS -> baseScore | _(run)_ |

## Curated Datatype Properties

| property | label | count |
| --- | --- | --- |
| cve:id | CVE id (literal) | _(run)_ |
| cve:description | CVE description | _(run)_ |
| dct:description | Description (Dublin Core, dipakai CWE & CAPEC) | _(run)_ |
| dct:issued | Issued date | _(run)_ |
| dct:modified | Modified date | _(run)_ |
| cwe:name | CWE name | _(run)_ |
| capec:name | CAPEC name | _(run)_ |
| cvss:baseScore | CVSS base score | _(run)_ |

## Sample Triples

_(diisi saat run)_