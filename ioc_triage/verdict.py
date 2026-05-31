def calculate_verdict(enrichment_results):
    verdict = "CLEAN / UNKNOWN"
    severity_score = 0
    reasons = []

    for result in enrichment_results:
        status = result.get("status")
        source = result.get("source")

        if status != "ok":
            continue

        if source == "AbuseIPDB":
            abuse_score = result.get("abuse_confidence_score", 0)

            if abuse_score >= 80:
                verdict = "MALICIOUS"
                severity_score = max(severity_score, abuse_score)
                reasons.append(
                    f"AbuseIPDB abuse confidence score is {abuse_score}."
                )

            elif abuse_score >= 25:
                if verdict != "MALICIOUS":
                    verdict = "SUSPICIOUS"
                severity_score = max(severity_score, abuse_score)
                reasons.append(
                    f"AbuseIPDB abuse confidence score is {abuse_score}."
                )

        elif source == "VirusTotal":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious >= 5:
                verdict = "MALICIOUS"
                severity_score = max(severity_score, 90)
                reasons.append(
                    f"VirusTotal reports {malicious} malicious detections."
                )

            elif malicious >= 1:
                if verdict != "MALICIOUS":
                    verdict = "SUSPICIOUS"
                severity_score = max(severity_score, 60)
                reasons.append(
                    f"VirusTotal reports {malicious} malicious detections."
                )

            elif suspicious > 0:
                if verdict != "MALICIOUS":
                    verdict = "SUSPICIOUS"
                severity_score = max(severity_score, 40)
                reasons.append(
                    f"VirusTotal reports {suspicious} suspicious detections."
                )

    if not reasons:
        reasons.append("No strong malicious indicators found in available sources.")

    recommendations = build_recommendations(verdict)

    return {
        "verdict": verdict,
        "severity_score": severity_score,
        "reasons": reasons,
        "recommendations": recommendations,
    }


def build_recommendations(verdict):
    if verdict == "MALICIOUS":
        return [
            "Block or monitor the IOC according to internal policy.",
            "Review related authentication, proxy, firewall or endpoint logs.",
            "Escalate to SOC Tier 2 if this IOC is linked to internal assets.",
        ]

    if verdict == "SUSPICIOUS":
        return [
            "Review additional context before taking blocking action.",
            "Check whether the IOC appears in internal logs.",
            "Monitor related activity and escalate if more evidence appears.",
        ]

    return [
        "No immediate blocking recommendation based only on available enrichment.",
        "Keep the result as CLEAN / UNKNOWN, not SAFE.",
        "Use incident context and internal telemetry before making a final decision.",
    ]