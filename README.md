# ioc-triage-cli

A small Python CLI for the first step of SOC triage: taking an indicator, figuring out what type it is, and preparing the project for passive enrichment and verdict scoring.

Right now it detects IOC types and performs basic AbuseIPDB enrichment for IPv4 indicators when the API key is configured. The code is structured so the next stages can be added without turning the CLI into one large file.

This is not a SIEM, scanner, sandbox, or exploitation tool. It's a learning and portfolio project built around a realistic SOC triage workflow.

---

## What it does

The tool accepts an IOC from the command line or from a text file and identifies its type.

Current supported types:

- IPv4
- domain
- URL
- MD5
- SHA256

For IPv4 indicators, the tool can also query AbuseIPDB and print basic reputation data.

Unsupported or invalid input returns `unknown`.

Example:

```bash
python -m ioc_triage 185.220.101.45
```

```text
IOC: 185.220.101.45
Type: ipv4
AbuseIPDB: {'source': 'AbuseIPDB', 'status': 'ok', 'abuse_confidence_score': 0, 'total_reports': 0, 'country_code': 'US', 'isp': 'Example ISP', 'domain': 'example.com', 'usage_type': 'Data Center/Web Hosting/Transit'}
```

If AbuseIPDB is not configured, IPv4 enrichment is skipped:

```text
IOC: 185.220.101.45
Type: ipv4
AbuseIPDB: {'source': 'AbuseIPDB', 'status': 'skipped', 'message': 'AbuseIPDB API key not configured.'}
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

The detection logic mainly uses the Python standard library. AbuseIPDB enrichment uses `requests`, and environment variable loading uses `python-dotenv`.

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

IOC: example.com
Type: domain

IOC: http://example.com/login
Type: url

IOC: 44d88612fea8a8f36de82e1278abb02f
Type: md5

IOC: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Type: sha256
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
| `ioc_triage/cli.py` | Argument parsing, single IOC mode, file mode, and calling IPv4 enrichment |
| `ioc_triage/detectors.py` | IOC type detection logic |
| `ioc_triage/enrichers/abuseipdb.py` | Basic AbuseIPDB lookup for IPv4 indicators |
| `ioc_triage/config.py` | Loads API keys and request timeout from environment variables |
| `ioc_triage/__main__.py` | Allows the tool to run with `python -m ioc_triage` |
| `examples/sample_iocs.txt` | Example input file for file mode |
| `tests/test_detectors.py` | Basic tests for detection logic |
| `.env.example` | Example environment configuration |

The remaining placeholder modules (`models.py`, `reporter.py`, `verdict.py`, `test_verdict.py`, `dns_lookup.py`, and `virustotal.py`) are part of the planned architecture. They are present in the repository to show the direction of the project, not to suggest that DNS lookup, VirusTotal enrichment, scoring, or reporting are already implemented.

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

The result is returned as a small dictionary and printed by the CLI. This is still an early enrichment stage, but it already shows how the project will connect IOC detection with passive Threat Intelligence sources.

---

## Tests

Run tests with:

```bash
python -m pytest
```

The current working tests cover valid examples for each supported IOC type and several invalid inputs, including an invalid IPv4 address and invalid domain formats.

---

## Environment variables

The project loads configuration from environment variables using `python-dotenv`.

For the current code, `.env` should contain:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
REQUEST_TIMEOUT=10
```

`ABUSEIPDB_API_KEY` is used by the current IPv4 enrichment logic. `VIRUSTOTAL_API_KEY` is already present for the planned VirusTotal integration.

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

The current version covers IOC type detection and the first basic enrichment source for IPv4 indicators.

Enrichment sources:

| Source | Status | Purpose |
|---|---|---|
| AbuseIPDB | Basic IPv4 lookup implemented | IP reputation lookup |
| VirusTotal | Planned | IP, domain, URL, and hash reputation lookup |
| DNS lookup | Planned | Basic domain resolution |

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

Next:

- [ ] Add VirusTotal enrichment for IPs, domains, URLs, and hashes
- [ ] Add DNS lookup for domains
- [ ] Normalize enrichment results
- [ ] Add verdict scoring
- [ ] Add formatted terminal output
- [ ] Add JSON export
- [ ] Add Markdown export
- [ ] Add tests for enrichment and verdict logic
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
