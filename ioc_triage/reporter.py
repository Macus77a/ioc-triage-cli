import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
    
console = Console()


def build_key_findings(source):
    source_name = source.get("source")

    if source_name == "AbuseIPDB":
        abuse_score = source.get("abuse_confidence_score", "N/A")
        total_reports = source.get("total_reports", "N/A")
        country_code = source.get("country_code", "N/A")

        return (
            f"Abuse score: {abuse_score}, "
            f"Reports: {total_reports}, "
            f"Country: {country_code}"
        )

    if source_name == "VirusTotal":
        malicious = source.get("malicious", "N/A")
        suspicious = source.get("suspicious", "N/A")
        harmless = source.get("harmless", "N/A")

        return (
            f"Malicious: {malicious}, "
            f"Suspicious: {suspicious}, "
            f"Harmless: {harmless}"
        )

    if source_name == "DNS":
        resolved_ips = source.get("resolved_ips", [])
        if resolved_ips:
            return f"Resolved IPs: {', '.join(resolved_ips)}"
        return "No resolved IPs"

    return "No key findings available"


def print_report(result):
    ioc = result.get("ioc", "Unknown IOC")
    ioc_type = result.get("ioc_type", "unknown")
    verdict = result.get("verdict", "No verdict")
    severity_score = result.get("severity_score", 0)

    summary = (
        f"[bold]IOC:[/bold] {ioc}\n"
        f"[bold]Type:[/bold] {ioc_type}\n"
        f"[bold]Verdict:[/bold] {verdict}\n"
        f"[bold]Severity score:[/bold] {severity_score}"
    )

    console.print(Panel(summary, title="IOC Triage Report", expand=False))

    sources = result.get("sources", [])

    if sources:
        table = Table(title="Threat Intelligence Sources")

        table.add_column("Source")
        table.add_column("Status")
        table.add_column("Key Findings")

        for source in sources:
            source_name = source.get("source", "Unknown")
            status = source.get("status", "unknown")
            key_findings = build_key_findings(source)

            table.add_row(source_name, status, key_findings)

        console.print(table)

    recommendations = result.get("recommendations", [])

    if recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for recommendation in recommendations:
            console.print(f"- {recommendation}")

def export_json(result, output_path):
    path = Path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    console.print(f"[green]JSON report saved to:[/green] {path}")