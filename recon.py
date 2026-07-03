import socket
import dns.resolver
import requests
import whois
from urllib.parse import urlparse


def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        return domain.replace("www.", "")
    except:
        return url


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unable to resolve IP"


def get_dns_records(domain):
    records = {}

    try:
        records["A"] = [str(ip) for ip in dns.resolver.resolve(domain, "A")]
    except:
        records["A"] = []

    try:
        records["MX"] = [str(mx.exchange) for mx in dns.resolver.resolve(domain, "MX")]
    except:
        records["MX"] = []

    try:
        records["NS"] = [str(ns.target) for ns in dns.resolver.resolve(domain, "NS")]
    except:
        records["NS"] = []

    return records


def get_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except:
        return {}


def get_whois(domain):
    try:
        w = whois.whois(domain)

        return {
            "registrar": w.registrar,
            "country": w.country,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date)
        }

    except:
        return {
            "error": "WHOIS data not available"
        }


def run_recon(url):
    domain = extract_domain(url)

    return {
        "domain": domain,
        "ip": get_ip(domain),
        "dns": get_dns_records(domain),
        "headers": get_headers(url),
        "whois": get_whois(domain)
    }