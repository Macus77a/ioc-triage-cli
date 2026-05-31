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
from ioc_triage.verdict import calculate_verdict
from ioc_triage.reporter import print_report, export_json


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

    parser.add_argument(
        "--export",
        help="Export the report in JSON format to the specified file",
    )

    return parser.parse_args()


def analyze_single_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)

    enrichment_results = []

    if ioc_type == "ipv4":
        abuseipdb_result = check_ip_abuseipdb(ioc)
        virustotal_result = check_ip_virustotal(ioc)

        enrichment_results.append(abuseipdb_result)
        enrichment_results.append(virustotal_result)
    
    elif ioc_type == "domain":
        dns_result = resolve_domain(ioc)
        virustotal_result = check_domain_virustotal(ioc)
        
        enrichment_results.append(dns_result)
        enrichment_results.append(virustotal_result)

    elif ioc_type == "url":
        virustotal_result = check_url_virustotal(ioc)
        enrichment_results.append(virustotal_result)
    
    elif ioc_type in ("md5", "sha256"):
        virustotal_result = check_hash_virustotal(ioc)
        enrichment_results.append(virustotal_result)

    elif ioc_type == "unknown":
        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "verdict": "CLEAN / UNKNOWN",
            "severity_score": 0,
            "sources": [],
            "recommendations": [
                "Unsupported or invalid IOC format. Verify the input value."
            ],
        }

    verdict_result = calculate_verdict(enrichment_results)

    result = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "verdict": verdict_result.get("verdict"),
        "severity_score": verdict_result.get("severity_score"),
        "sources": enrichment_results,
        "recommendations": verdict_result.get("recommendations", []),
    }

    return result

def main():
    args = parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as file:
                for line in file:
                    ioc = line.strip()

                    if not ioc or ioc.startswith("#"):
                        continue

                    result = analyze_single_ioc(ioc)
                    print_report(result)
                    print()

        except FileNotFoundError:
            print(f"Error: file not found: {args.file}")

        return

    if args.ioc:
        result = analyze_single_ioc(args.ioc)
        print_report(result)

        if args.export:
            export_json(result, args.export)

        return

    print("Error: provide an IOC or use --file")