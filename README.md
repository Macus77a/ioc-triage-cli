# ioc-triage-cli

A small Python CLI for the first step of SOC triage: taking an indicator, figuring out what type it is, and enriching it with passive Threat Intelligence sources before later verdict scoring and reporting stages.

Right now it detects IOC types and performs basic enrichment using AbuseIPDB for IPv4 indicators, VirusTotal for IPv4/domain/URL/hash indicators, and DNS lookup for domains. The code is structured so the next stages can be added without turning the CLI into one large file.

This is not a SIEM, scanner, sandbox, or exploitation tool. It's a learning and portfolio project built around a realistic SOC triage workflow.

---

## What it does

The tool accepts an IOC from the command line or from a text file, identifies its type, and runs passive enrichment depending on the IOC type.

Current supported types:

- IPv4
- domain
- URL
- MD5
- SHA256

Current enrichment behavior:

- IPv4 indicators are checked with AbuseIPDB and VirusTotal
- domains are resolved with DNS lookup and checked with VirusTotal
- URLs are checked with VirusTotal
- MD5 and SHA256 hashes are checked with VirusTotal

Unsupported or invalid input returns `unknown`.

Example:

```bash
python -m ioc_triage 185.220.101.45
```

```text
IOC: 185.220.101.45
Type: ipv4
AbuseIPDB: {'source': 'AbuseIPDB', 'status': 'ok', 'abuse_confidence_score': 0, 'total_reports': 0, 'country_code': 'US', 'isp': 'Example ISP', 'domain': 'example.com', 'usage_type': 'Data Center/Web Hosting/Transit'}
VirusTotal: {'source': 'VirusTotal', 'status': 'ok', 'malicious': 0, 'suspicious': 0, 'harmless': 61, 'undetected': 30}
```

If an API key is not configured, that enrichment source is skipped:

```text
IOC: 185.220.101.45
Type: ipv4
AbuseIPDB: {'source': 'AbuseIPDB', 'status': 'skipped', 'message': 'AbuseIPDB API key not configured.'}
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}
```

Example domain analysis:

```bash
python -m ioc_triage example.com
```

```text
IOC: example.com
Type: domain
DNS Lookup: {'source': 'DNS Lookup', 'status': 'ok', 'resolved_ips': ['93.184.216.34']}
VirusTotal: {'source': 'VirusTotal', 'status': 'ok', 'malicious': 0, 'suspicious': 0, 'harmless': 61, 'undetected': 30}
```

If the input is not recognized:

```text
IOC: not an ioc
Type: unknown
Status: unsupported or invalid IOC format
```

---

## Getting started

```bash
git clone <repository-url>
cd ioc-triage-cli

python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The detection logic mainly uses the Python standard library. AbuseIPDB and VirusTotal enrichment use `requests`, DNS lookup uses `dnspython`, and environment variable loading uses `python-dotenv`.

---

## Usage

Single IOC mode:

```bash
python -m ioc_triage 185.220.101.45
python -m ioc_triage example.com
python -m ioc_triage http://example.com/login
python -m ioc_triage 44d88612fea8a8f36de82e1278abb02f
python -m ioc_triage e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

File mode:

```bash
python -m ioc_triage --file examples/sample_iocs.txt
```

The file should contain one IOC per line. Empty lines and lines starting with `#` are skipped.

Example input:

```text
# Sample IOC list for local testing.
# Used later for --file mode.
192.0.2.10
example.com
http://example.com/login
44d88612fea8a8f36de82e1278abb02f
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Example output:

```text
IOC: 192.0.2.10
Type: ipv4
AbuseIPDB: {'source': 'AbuseIPDB', 'status': 'skipped', 'message': 'AbuseIPDB API key not configured.'}
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}

IOC: example.com
Type: domain
DNS Lookup: {'source': 'DNS Lookup', 'status': 'ok', 'resolved_ips': ['93.184.216.34']}
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}

IOC: http://example.com/login
Type: url
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}

IOC: 44d88612fea8a8f36de82e1278abb02f
Type: md5
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}

IOC: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Type: sha256
VirusTotal: {'source': 'VirusTotal', 'status': 'skipped', 'message': 'VirusTotal API key not configured.'}
```

---

## Project structure

```text
ioc-triage-cli/
│
├── examples/
│   └── sample_iocs.txt
│
├── ioc_triage/
│   ├── enrichers/
│   │   ├── __init__.py
│   │   ├── abuseipdb.py
│   │   ├── dns_lookup.py
│   │   └── virustotal.py
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── detectors.py
│   ├── models.py
│   ├── reporter.py
│   └── verdict.py
│
├── tests/
│   ├── test_detectors.py
│   └── test_verdict.py
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

Main files:

| File | Purpose |
|---|---|
| `ioc_triage/cli.py` | Argument parsing, single IOC mode, file mode, and calling enrichment logic |
| `ioc_triage/detectors.py` | IOC type detection logic |
| `ioc_triage/enrichers/abuseipdb.py` | Basic AbuseIPDB lookup for IPv4 indicators |
| `ioc_triage/enrichers/virustotal.py` | Basic VirusTotal lookup for IPv4, domains, URLs, MD5 hashes, and SHA256 hashes |
| `ioc_triage/enrichers/dns_lookup.py` | Basic DNS A record lookup for domains |
| `ioc_triage/config.py` | Loads API keys and request timeout from environment variables |
| `ioc_triage/__main__.py` | Allows the tool to run with `python -m ioc_triage` |
| `examples/sample_iocs.txt` | Example input file for file mode |
| `tests/test_detectors.py` | Basic tests for detection logic |
| `.env.example` | Example environment configuration |

The remaining placeholder modules (`models.py`, `reporter.py`, `verdict.py`, and `test_verdict.py`) are part of the planned architecture. They are present in the repository to show the direction of the project, not to suggest that scoring or reporting is already implemented.

---

## Detection logic

Detection lives in `detectors.py` and is split into small functions:

- `is_ipv4()`
- `is_url()`
- `is_domain()`
- `is_md5()`
- `is_sha256()`
- `detect_ioc_type()`

The CLI passes input to `detect_ioc_type()` and prints the result. This keeps input/output handling separate from classification logic.

Current detection order:

```text
URL → IPv4 → MD5 → SHA256 → domain → unknown
```

Order matters here — some values can match multiple patterns depending on how broadly you define them.

---

## AbuseIPDB enrichment

IPv4 indicators are passed to `check_ip_abuseipdb()` after the type is detected.

The current AbuseIPDB integration handles:

- missing API key
- successful response
- rate limit response
- non-200 HTTP response
- timeout
- request error
- invalid JSON response

The result is returned as a small dictionary and printed by the CLI. This is still an early enrichment stage, but it already shows how the project connects IOC detection with passive Threat Intelligence sources.

---

## VirusTotal enrichment

IPv4, domain, URL, MD5, and SHA256 indicators are passed to the proper VirusTotal helper after the type is detected.

The current VirusTotal integration handles:

- missing API key
- successful response
- rate limit response
- non-200 HTTP response
- timeout
- request error
- invalid JSON response

The current output focuses on the basic `last_analysis_stats` values:

- `malicious`
- `suspicious`
- `harmless`
- `undetected`

This keeps the first version simple while still making the output useful for initial IOC triage.

---

## DNS lookup

Domain indicators are passed to `resolve_domain()` after the type is detected.

The current DNS lookup checks A records and handles:

- successful resolution
- domain not found
- existing domain with no A record
- timeout
- DNS-related errors

The result is returned as a small dictionary and printed by the CLI before the VirusTotal result for domains.

---

## Tests

Run tests with:

```bash
python -m pytest
```

The current working tests cover valid examples for each supported IOC type and several invalid inputs, including an invalid IPv4 address and invalid domain formats.

Enrichment modules are not covered by tests yet.

---

## Environment variables

The project loads configuration from environment variables using `python-dotenv`.

For the current code, `.env` should contain:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
REQUEST_TIMEOUT=10
```

`ABUSEIPDB_API_KEY` is used by the AbuseIPDB IPv4 enrichment logic. `VIRUSTOTAL_API_KEY` is used by the VirusTotal enrichment logic for IPv4 indicators, domains, URLs, MD5 hashes, and SHA256 hashes. `REQUEST_TIMEOUT` controls request timeouts for API calls and DNS lookup.

The actual `.env` file should not be committed.

---

## Planned workflow

```text
Input IOC
  → Detect type
  → Enrich using passive sources
  → Normalize results
  → Score verdict
  → Print or export report
```

The current version covers IOC type detection, basic passive enrichment, and simple terminal output. Normalized result models, verdict scoring, and report export are still planned.

Enrichment sources:

| Source | Status | Purpose |
|---|---|---|
| AbuseIPDB | Basic IPv4 lookup implemented | IP reputation lookup |
| VirusTotal | Basic lookup implemented for IPv4, domains, URLs, MD5, and SHA256 | IP, domain, URL, and hash reputation lookup |
| DNS lookup | Basic A record lookup implemented | Basic domain resolution |

Planned verdict levels:

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | Strong malicious signals from enrichment sources |
| `SUSPICIOUS` | Weak or low-confidence suspicious signals |
| `UNKNOWN` | No strong signal from the checked sources |

The project avoids calling an IOC `SAFE`. Lack of detection does not prove that an indicator is harmless.

---

## Roadmap

Done:

- [x] CLI entry point with `python -m ioc_triage`
- [x] Single IOC mode
- [x] File mode
- [x] IOC type detector
- [x] Basic detector tests
- [x] `.env.example`
- [x] Placeholder modules for next stages
- [x] Load configuration from environment variables
- [x] Add AbuseIPDB enrichment for IPv4 indicators
- [x] Add VirusTotal enrichment for IPv4, domains, URLs, MD5, and SHA256
- [x] Add DNS lookup for domains

Next:

- [ ] Normalize enrichment results
- [ ] Add verdict scoring
- [ ] Add formatted terminal output
- [ ] Add JSON export
- [ ] Add Markdown export
- [ ] Add tests for AbuseIPDB, VirusTotal, DNS lookup, and verdict logic
- [ ] Add example reports

---

## Notes

This tool is for passive IOC triage only.

It does not:

- scan hosts
- exploit systems
- brute force services
- download malware
- submit automatic abuse reports
- modify external systems

Threat Intelligence data always needs context. Public sources can miss threats, return outdated information, or produce false positives. The tool is meant to support triage, not replace analyst judgment.

---

## License

Created for learning and portfolio purposes.
