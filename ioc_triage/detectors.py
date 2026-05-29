import ipaddress
import re
from urllib.parse import urlparse

def is_ipv4(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False
    
def is_url(value):
    
    if not isinstance(value, str):
        return False
        
    parsed_url = urlparse(value.strip())

    return (
        parsed_url.scheme in ("http", "https")
        and bool(parsed_url.netloc)
    )

def is_domain(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    return re.fullmatch(pattern, value) is not None
    
def is_md5(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    return re.fullmatch(r"[a-fA-F0-9]{32}", value) is not None
    
def is_sha256(value):
    if not isinstance(value, str):
        return False
    
    value = value.strip()
    
    pattern = r"[0-9a-fA-F]{64}"

    return re.fullmatch(pattern, value) is not None

    

def detect_ioc_type(value):
    if is_url(value):
        return "url"
    
    if is_ipv4(value):
        return "ipv4"
    
    if is_md5(value):
        return "md5"
    
    if is_sha256(value):
        return "sha256"
    
    if is_domain(value):
        return "domain"
    
    return "unknown"
