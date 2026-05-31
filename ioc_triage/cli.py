import argparse

from ioc_triage.detectors import detect_ioc_type
from ioc_triage.enrichers.abuseipdb import check_ip_abuseipdb
from ioc_triage.enrichers.virustotal import (
    check_hash_virustotal,
    check_ip_virustotal,
    check_domain_virustotal,
    check_url_virustotal,
)
from ioc_triage.enrichers.dns_lookup import resolve_domain


def parse_args():
    parser = argparse.ArgumentParser(
        description="IOC Triage CLI - initial IOC type detection and triage helper"
    )

    parser.add_argument(
        "ioc",
        nargs="?",
        help="Indicator of Compromise to analyze, e.g. IP, domain, URL or hash",
    )

    parser.add_argument(
        "--file",
        help="Path to a file containing IOC values, one per line",
    )

    return parser.parse_args()


def analyze_single_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)

    print(f"IOC: {ioc}")
    print(f"Type: {ioc_type}")

    if ioc_type == "ipv4":
        abuseipdb_result = check_ip_abuseipdb(ioc)
        virustotal_result = check_ip_virustotal(ioc)

        print(f"AbuseIPDB: {abuseipdb_result}")
        print(f"VirusTotal: {virustotal_result}")

    elif ioc_type == "domain":
        dns_result = resolve_domain(ioc)
        virustotal_result = check_domain_virustotal(ioc)
        
        print(f"DNS Lookup: {dns_result}")
        print(f"VirusTotal: {virustotal_result}")

    elif ioc_type == "url":
        virustotal_result = check_url_virustotal(ioc)
        print(f"VirusTotal: {virustotal_result}")

    elif ioc_type in ("md5", "sha256"):
        virustotal_result = check_hash_virustotal(ioc)
        print(f"VirusTotal: {virustotal_result}")
    
    elif ioc_type == "unknown":
        print("Status: unsupported or invalid IOC format")


def main():
    args = parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as file:
                for line in file:
                    ioc = line.strip()

                    if not ioc or ioc.startswith("#"):
                        continue

                    analyze_single_ioc(ioc)
                    print()

        except FileNotFoundError:
            print(f"Error: file not found: {args.file}")

        return

    if args.ioc:
        analyze_single_ioc(args.ioc)
        return

    print("Error: provide an IOC or use --file")