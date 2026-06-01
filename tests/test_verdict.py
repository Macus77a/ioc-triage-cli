from ioc_triage.verdict import calculate_verdict


def test_verdict_malicious_from_abuseipdb():
    result = calculate_verdict([
        {
            "source": "AbuseIPDB",
            "status": "ok",
            "abuse_confidence_score": 90,
        }
    ])

    assert result["verdict"] == "MALICIOUS"
    assert result["severity_score"] == 90
    assert "AbuseIPDB abuse confidence score is 90." in result["reasons"]


def test_verdict_suspicious_from_abuseipdb():
    result = calculate_verdict([
        {
            "source": "AbuseIPDB",
            "status": "ok",
            "abuse_confidence_score": 40,
        }
    ])

    assert result["verdict"] == "SUSPICIOUS"
    assert result["severity_score"] == 40
    assert "AbuseIPDB abuse confidence score is 40." in result["reasons"]


def test_verdict_malicious_from_virustotal():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": 5,
            "suspicious": 0,
        }
    ])

    assert result["verdict"] == "MALICIOUS"
    assert result["severity_score"] == 90
    assert "VirusTotal reports 5 malicious detections." in result["reasons"]


def test_verdict_suspicious_from_single_virustotal_detection():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": 1,
            "suspicious": 0,
        }
    ])

    assert result["verdict"] == "SUSPICIOUS"
    assert result["severity_score"] == 60
    assert "VirusTotal reports 1 malicious detections." in result["reasons"]


def test_verdict_suspicious_from_virustotal_suspicious_detection():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": 0,
            "suspicious": 2,
        }
    ])

    assert result["verdict"] == "SUSPICIOUS"
    assert result["severity_score"] == 40
    assert "VirusTotal reports 2 suspicious detections." in result["reasons"]


def test_verdict_clean_unknown_when_no_strong_indicators():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": 0,
            "suspicious": 0,
        }
    ])

    assert result["verdict"] == "CLEAN / UNKNOWN"
    assert result["severity_score"] == 0
    assert result["reasons"] == [
        "No strong malicious indicators found in available sources."
    ]


def test_verdict_ignores_skipped_or_error_sources():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "skipped",
            "malicious": 10,
            "suspicious": 5,
        },
        {
            "source": "AbuseIPDB",
            "status": "error",
            "abuse_confidence_score": 100,
        },
    ])

    assert result["verdict"] == "CLEAN / UNKNOWN"
    assert result["severity_score"] == 0
    assert result["reasons"] == [
        "No strong malicious indicators found in available sources."
    ]


def test_verdict_keeps_malicious_when_suspicious_source_appears_later():
    result = calculate_verdict([
        {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": 5,
            "suspicious": 0,
        },
        {
            "source": "AbuseIPDB",
            "status": "ok",
            "abuse_confidence_score": 30,
        },
    ])

    assert result["verdict"] == "MALICIOUS"
    assert result["severity_score"] == 90