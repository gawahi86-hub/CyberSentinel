# ---------------------------------
# CyberSentinel v2.0
# Professional Website Security Scanner
# ---------------------------------

import socket
import ssl
import requests
import time

from urllib.parse import urlparse
from datetime import datetime


# ---------------------------------
# Common Ports
# ---------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Proxy"
}


# ---------------------------------
# URL Normalization
# ---------------------------------

def normalize_url(url):

    url = url.strip()
    url = url.replace(" ", "")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url



# ---------------------------------
# IP Resolution
# ---------------------------------

def get_ip(domain):

    try:
        return socket.gethostbyname(domain)

    except:
        return "Unknown"



# ---------------------------------
# SSL Certificate Scanner
# ---------------------------------

def check_ssl(domain):

    result = {

        "status": "Unknown",
        "issuer": "Unknown",
        "expiry": "Unknown",
        "days_remaining": 0

    }


    try:

        context = ssl.create_default_context()


        with socket.create_connection(
            (domain,443),
            timeout=5
        ) as sock:


            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:


                certificate = ssock.getpeercert()


                expiry = certificate["notAfter"]


                expiry_date = datetime.strptime(
                    expiry,
                    "%b %d %H:%M:%S %Y %Z"
                )


                days = (
                    expiry_date -
                    datetime.utcnow()
                ).days



                result["status"] = "Valid"

                result["expiry"] = str(
                    expiry_date.date()
                )

                result["days_remaining"] = days


                result["issuer"] = dict(
                    x[0]
                    for x in certificate["issuer"]
                ).get(
                    "organizationName",
                    "Unknown"
                )



    except:

        result["status"] = "Invalid"



    return result



# ---------------------------------
# Port Scanner
# ---------------------------------

def check_open_ports(domain):

    ports = []


    for port, service in COMMON_PORTS.items():


        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )


            sock.settimeout(0.5)


            result = sock.connect_ex(
                (domain, port)
            )


            if result == 0:

                ports.append({

                    "port": port,

                    "service": service

                })


            sock.close()


        except:

            pass



    return ports



# ---------------------------------
# Technology Detection
# ---------------------------------

def detect_technology(headers):

    technologies = []


    server = headers.get(
        "Server",
        ""
    )


    powered = headers.get(
        "X-Powered-By",
        ""
    )


    combined = (
        server +
        " " +
        powered
    ).lower()



    technologies_map = {


        "nginx":
        "Nginx",


        "apache":
        "Apache",


        "cloudflare":
        "Cloudflare",


        "php":
        "PHP",


        "wordpress":
        "WordPress",


        "react":
        "React"


    }



    for key,value in technologies_map.items():

        if key in combined:

            technologies.append(value)



    if not technologies:

        technologies.append(
            "Not Disclosed"
        )


    return technologies



# ---------------------------------
# Security Header Scanner
# ---------------------------------

def analyze_headers(headers):

    findings = []


    security_headers = {


        "Content-Security-Policy":{

            "title":
            "Missing Content Security Policy",

            "severity":
            "Medium",

            "cvss":
            5.3,

            "owasp":
            "A05:2021 Security Misconfiguration",

            "fix":
            "Implement Content-Security-Policy header."

        },


        "Strict-Transport-Security":{

            "title":
            "Missing HTTPS Security Policy",

            "severity":
            "Medium",

            "cvss":
            5.3,

            "owasp":
            "A02:2021 Cryptographic Failures",

            "fix":
            "Enable HSTS header."

        },


        "X-Frame-Options":{

            "title":
            "Missing Clickjacking Protection",

            "severity":
            "Medium",

            "cvss":
            4.7,

            "owasp":
            "A05:2021 Security Misconfiguration",

            "fix":
            "Enable X-Frame-Options."

        },


        "X-Content-Type-Options":{

            "title":
            "Missing MIME Protection",

            "severity":
            "Low",

            "cvss":
            3.1,

            "owasp":
            "A05:2021 Security Misconfiguration",

            "fix":
            "Enable X-Content-Type-Options."

        },


        "Referrer-Policy":{

            "title":
            "Missing Referrer Policy",

            "severity":
            "Low",

            "cvss":
            3.1,

            "owasp":
            "A05:2021 Security Misconfiguration",

            "fix":
            "Configure Referrer-Policy header."

        }


    }



    for header,data in security_headers.items():

        if header not in headers:


            findings.append({

                "title":
                data["title"],

                "name":
                data["title"],

                "severity":
                data["severity"],

                "cvss":
                data["cvss"],

                "owasp":
                data["owasp"],

                "simple_explanation":
                data["title"],

                "technical_explanation":
                data["title"],

                "description":
                "Security header not detected.",

                "business_impact":
                "May increase website attack surface.",

                "recommendation":
                data["fix"]

            })



    return findings



# ---------------------------------
# Cookie Scanner
# ---------------------------------

def analyze_cookies(cookies):

    findings=[]


    for cookie in cookies:


        if not cookie.secure:

            findings.append({

                "title":
                "Cookie Missing Secure Flag",

                "name":
                "Cookie Missing Secure Flag",

                "severity":
                "Low",

                "cvss":
                3.1,

                "owasp":
                "A05 Security Misconfiguration",

                "description":
                f"{cookie.name} does not use Secure flag.",

                "recommendation":
                "Enable Secure cookie attribute."

            })



        if not cookie.has_nonstandard_attr("HttpOnly"):


            findings.append({

                "title":
                "Cookie Missing HttpOnly Flag",

                "name":
                "Cookie Missing HttpOnly Flag",

                "severity":
                "Medium",

                "cvss":
                4.7,

                "owasp":
                "A07 Identification and Authentication Failures",

                "description":
                f"{cookie.name} may be accessible by scripts.",

                "recommendation":
                "Enable HttpOnly attribute."

            })


    return findings



# ---------------------------------
# Main Scanner
# ---------------------------------

def scan_website(url):

    try:

        url = normalize_url(url)


        parsed = urlparse(url)

        domain = parsed.netloc



        start=time.time()



        response=requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={

                "User-Agent":
                "CyberSentinel Security Scanner"

            }

        )



        response_time=round(

            (time.time()-start)*1000,

            2

        )



        headers=dict(
            response.headers
        )


        findings=[]


        findings.extend(
            analyze_headers(headers)
        )


        findings.extend(
            analyze_cookies(
                response.cookies
            )
        )


        ports=check_open_ports(domain)


        ssl_info=check_ssl(domain)



        return {


            "url":
            response.url,


            "ip":
            get_ip(domain),


            "ssl":
            ssl_info,


            "headers":
            headers,


            "ports":
            ports,


            "technology":
            detect_technology(headers),


            "server":
            headers.get(
                "Server",
                "Unknown"
            ),


            "http_status":
            response.status_code,


            "response_time":
            response_time,


            "findings":
            findings,


            "risk_score":
            0,


            "scan_status":
            "Success"


        }



    except Exception as e:


        return {


            "url":
            url,


            "ip":
            "Unknown",


            "ssl":
            {

                "status":
                "Failed"

            },


            "ports":[],

            "technology":[],

            "findings":[{


                "title":
                "Scan Failed",

                "severity":
                "INFO",

                "cvss":
                0,

                "description":
                str(e),

                "recommendation":
                "Check website URL."

            }],


            "risk_score":
            0,


            "scan_status":
            "Failed"


        }