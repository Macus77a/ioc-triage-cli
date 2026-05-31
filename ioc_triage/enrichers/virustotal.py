import requests

from ioc_triage.config import VIRUSTOTAL_API_KEY, REQUEST_TIMEOUT


def check_ip_virustotal(ip_address):
    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "skipped",
            "message": "VirusTotal API key not configured.",
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "Accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            return {
                "source": "VirusTotal",
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached.",
            }

        if response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "message": f"VirusTotal returned status code {response.status_code}.",
            }

        virustotal_report = response.json()

        stats = (
            virustotal_report
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.exceptions.Timeout:
        return {
            "source": "VirusTotal",
            "status": "timeout",
            "message": "VirusTotal request timed out.",
        }

    except requests.exceptions.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": f"VirusTotal request failed: {error}",
        }

    except ValueError:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "VirusTotal returned invalid JSON.",
        }
    
def check_domain_virustotal(domain):
    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "skipped",
            "message": "VirusTotal API key not configured.",
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "Accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            return {
                "source": "VirusTotal",
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached.",
            }

        if response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "message": f"VirusTotal returned status code {response.status_code}.",
            }

        virustotal_report = response.json()

        stats = (
            virustotal_report
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.exceptions.Timeout:
        return {
            "source": "VirusTotal",
            "status": "timeout",
            "message": "VirusTotal request timed out.",
        }

    except requests.exceptions.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": f"VirusTotal request failed: {error}",
        }

    except ValueError:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "VirusTotal returned invalid JSON.",
        } 
    
def check_hash_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return {
            "source": "VirusTotal",
            "status": "skipped",
            "message": "VirusTotal API key not configured.",
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "Accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            return {
                "source": "VirusTotal",
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached.",
            }

        if response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "message": f"VirusTotal returned status code {response.status_code}.",
            }

        virustotal_report = response.json()

        stats = (
            virustotal_report
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.exceptions.Timeout:
        return {
            "source": "VirusTotal",
            "status": "timeout",
            "message": "VirusTotal request timed out.",
        }

    except requests.exceptions.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": f"VirusTotal request failed: {error}",
        }

    except ValueError:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": "VirusTotal returned invalid JSON.",
        }