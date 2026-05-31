import dns.resolver
import dns.exception

from ioc_triage.config import REQUEST_TIMEOUT

def resolve_domain(domain):
    
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=REQUEST_TIMEOUT)

        resolved_ips = []    
    
        for answer in answers:
            resolved_ips.append(answer.to_text())
    
        return {
            "source": "DNS Lookup",
            "status": "ok",
            "resolved_ips": resolved_ips,
        } 
    
    except dns.resolver.NXDOMAIN:
        return {
            "source": "DNS Lookup",
            "status": "not_found",
            "message": f"Domain {domain} does not exist.",
        }

    except dns.resolver.NoAnswer:
        return {
            "source": "DNS Lookup",
            "status": "no_answer",
            "message": f"Domain {domain} exists but has no A record.",
        }

    except dns.exception.Timeout:
        return {
            "source": "DNS Lookup",
            "status": "timeout",
            "message": f"Timeout occurred while resolving domain {domain}.",
        }

    except dns.exception.DNSException as error:
        return {
            "source": "DNS Lookup",
            "status": "error",
            "message": f"An error occurred while resolving domain {domain}: {str(error)}",
        }
