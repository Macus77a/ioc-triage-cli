# ioc-triage-cli

A small Python CLI for the first step of SOC triage: taking an indicator, figuring out what type it is, and preparing the project for passive enrichment and verdict scoring.

Right now it does one thing — IOC type detection — and the code is structured so the next stages can be added without turning the CLI into one large file.

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

Unsupported or invalid input returns `unknown`.

Example:

```bash
python -m ioc_triage 185.220.101.45
```

```text
IOC: 185.220.101.45
Type: ipv4
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

The current detection and CLI logic mainly use the Python standard library. Some dependencies are already included for tests and planned next stages.

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
| `ioc_triage/cli.py` | Argument parsing, single IOC mode, and file mode |
| `ioc_triage/detectors.py` | IOC type detection logic |
| `ioc_triage/__main__.py` | Allows the tool to run with `python -m ioc_triage` |
| `examples/sample_iocs.txt` | Example input file for file mode |
| `tests/test_detectors.py` | Basic tests for detection logic |
| `.env.example` | Placeholder for future API keys |

The placeholder modules (`config.py`, `models.py`, `reporter.py`, `verdict.py`, `test_verdict.py`, and the files inside `enrichers/`) are part of the planned architecture. They are present in the repository to show the direction of the project, not to suggest that enrichment, scoring, or reporting are already implemented.

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

## Tests

Run tests with:

```bash
python -m pytest
```

The current working tests cover valid examples for each supported IOC type and several invalid inputs, including an invalid IPv4 address and invalid domain formats.

---

## Environment variables

The repository includes `.env.example` for future API integrations:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

API key loading is not implemented in the current working CLI yet. The actual `.env` file should not be committed.

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

The current version covers the first part of this workflow.

Planned enrichment sources:

| Source | Planned purpose |
|---|---|
| AbuseIPDB | IP reputation lookup |
| VirusTotal | IP, domain, URL, and hash reputation lookup |
| DNS lookup | Basic domain resolution |

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

Next:

- [ ] Load configuration from environment variables
- [ ] Add AbuseIPDB enrichment for IPv4 indicators
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
