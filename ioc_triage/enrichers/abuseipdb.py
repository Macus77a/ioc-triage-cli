import requests
from ioc_triage.config import ABUSEIPDB_API_KEY, REQUEST_TIMEOUT

def check_ip_abuseipdb(ip_address):
    if not ABUSEIPDB_API_KEY:
        return {
            "source": "AbuseIPDB",
            "status": "skipped",
            "message": "AbuseIPDB API key not configured."
        }
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url, headers=headers, params=params, timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            return {
                "source": "AbuseIPDB",
                "status": "rate_limited",
                "message": "AbuseIPDB rate limit reached.",
            }

        if response.status_code != 200:
            return {
                "source": "AbuseIPDB",
                "status": "error",
                "message": f"AbuseIPDB returned status code {response.status_code}.",
            }

        abuseipdb_report = response.json()
        data = abuseipdb_report.get("data", {})

        return {
            "source": "AbuseIPDB",
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
        }

    except requests.exceptions.Timeout:
        return {
            "source": "AbuseIPDB",
            "status": "timeout",
            "message": "AbuseIPDB request timed out.",
        }

    except requests.exceptions.RequestException as error:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "message": f"AbuseIPDB request failed: {error}",
        }

    except ValueError:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "message": "AbuseIPDB returned invalid JSON.",
        }
    

