# ---------------------------------
# CyberSentinel v2.1
# Professional Website Security Scanner
# ---------------------------------

import socket
import ssl
import time
import requests

from datetime import datetime
from urllib.parse import urlparse


COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    3306,
    8080
]


# ---------------------------------
# URL NORMALIZATION
# ---------------------------------

def normalize_url(url):

    url = url.strip()

    url = url.replace(
        " ",
        ""
    )


    # Fix typing mistakes

    url = url.replace(
        "w.w.w.",
        "www."
    )

    url = url.replace(
        "ww.w.",
        "www."
    )

    url = url.replace(
        "www..",
        "www."
    )


    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url


    return url





# ---------------------------------
# IP INFORMATION
# ---------------------------------

def get_ip(domain):

    try:

        return socket.gethostbyname(
            domain
        )

    except:

        return "Unknown"





# ---------------------------------
# SSL CERTIFICATE CHECK
# ---------------------------------

def check_ssl(domain):

    try:

        context = ssl.create_default_context()


        with socket.create_connection(
            (domain,443),
            timeout=5
        ) as sock:


            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssl_socket:


                certificate = ssl_socket.getpeercert()


                expiry = certificate.get(
                    "notAfter",
                    ""
                )


                issuer = certificate.get(
                    "issuer",
                    ""
                )


                return {

                    "status":
                    "Valid",

                    "issuer":
                    str(issuer),

                    "expiry":
                    expiry,

                    "days_remaining":
                    "Available"

                }


    except:


        return {

            "status":
            "Failed",

            "issuer":
            "",

            "expiry":
            "",

            "days_remaining":
            0

        }





# ---------------------------------
# PORT SCANNER
# ---------------------------------

def scan_ports(domain):

    ports = []


    for port in COMMON_PORTS:


        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )


            sock.settimeout(
                0.5
            )


            result = sock.connect_ex(
                (
                    domain,
                    port
                )
            )


            if result == 0:


                service = "Unknown"


                if port == 80:
                    service = "HTTP"


                elif port == 443:
                    service = "HTTPS"



                ports.append({

                    "port":
                    port,

                    "service":
                    service

                })


            sock.close()



        except:

            pass



    return ports





# ---------------------------------
# SECURITY HEADERS
# ---------------------------------

def analyze_headers(headers):

    findings = []


    security_headers = {


        "Content-Security-Policy": {

            "name":
            "Missing Content Security Policy",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "owasp":
            "A05:2021 Security Misconfiguration",

            "component":
            "Website Security Configuration",

            "fix":
            "Enable Content-Security-Policy security header."

        },


        "Strict-Transport-Security": {

            "name":
            "Missing HTTPS Security Policy",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "owasp":
            "A02:2021 Cryptographic Failures",

            "component":
            "Website Security Configuration",

            "fix":
            "Enable Strict-Transport-Security security header."

        },


        "X-Content-Type-Options": {

            "name":
            "Missing MIME Protection",

            "cvss":
            3.1,

            "severity":
            "Low",

            "owasp":
            "A05:2021 Security Misconfiguration",

            "component":
            "Website Security Configuration",

            "fix":
            "Enable X-Content-Type-Options security header."

        },


        "Referrer-Policy": {

            "name":
            "Missing Referrer Policy",

            "cvss":
            3.1,

            "severity":
            "Low",

            "owasp":
            "A05:2021 Security Misconfiguration",

            "component":
            "Website Security Configuration",

            "fix":
            "Enable Referrer-Policy security header."

        }

    }



    for header,data in security_headers.items():


        if header not in headers:


            findings.append({

                "name":
                data["name"],


                "cvss":
                data["cvss"],


                "severity":
                data["severity"],


                "owasp":
                data["owasp"],


                "affected_component":
                data["component"],


                "impact":
                "May increase website attack surface.",


                "description":
                "Security header is missing.",


                "technical_explanation":
                "Security header is missing.",


                "recommendation":
                data["fix"]

            })



    return findings





# ---------------------------------
# COOKIE ANALYSIS
# ---------------------------------

def analyze_cookies(cookies):

    findings = []


    for cookie in cookies:


        if not cookie.secure:


            findings.append({

                "name":
                "Cookie Missing Secure Flag",


                "cvss":
                3.1,


                "severity":
                "Low",


                "owasp":
                "A05:2021 Security Misconfiguration",


                "affected_component":
                "Website Cookies",


                "impact":
                "Improper cookie security may expose session information.",


                "description":
                cookie.name,


                "recommendation":
                "Enable Secure cookie attribute."

            })



    return findings





# ---------------------------------
# MAIN WEBSITE SCANNER
# ---------------------------------

def scan_website(url):


    try:


        url = normalize_url(
            url
        )


        start = time.time()



        response = requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={

                "User-Agent":
                "Mozilla/5.0 CyberSentinel Security Scanner"

            }

        )



        response_time = round(

            (
                time.time()
                -
                start
            )
            *
            1000,

            2

        )



        parsed = urlparse(
            response.url
        )


        domain = parsed.netloc



        findings = []



        findings.extend(

            analyze_headers(
                response.headers
            )

        )



        findings.extend(

            analyze_cookies(
                response.cookies
            )

        )



        return {


            "url":
            response.url,


            "ip":
            get_ip(
                domain
            ),


            "http_status":
            response.status_code,


            "server":
            response.headers.get(
                "Server",
                "Unknown"
            ),


            "technology":
            response.headers.get(
                "X-Powered-By",
                "Not Disclosed"
            ),


            "ssl":
            check_ssl(
                domain
            ),


            "ports":
            scan_ports(
                domain
            ),


            "response_time":
            response_time,


            "findings":
            findings,


            "scanner_version":
            "CyberSentinel v2.1",


            "scan_time":
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            ),


            "scan_status":
            "Success"

        }





    except Exception as e:


        return {


            "url":
            url,


            "ip":
            "Unknown",


            "http_status":
            "Unavailable",


            "server":
            "Unknown",


            "technology":
            "Unknown",


            "ssl":
            {
                "status":
                "Failed"
            },


            "ports":
            [],


            "response_time":
            0,


            "findings":[{


                "name":
                "Scan Failed",


                "cvss":
                0,


                "severity":
                "INFO",


                "owasp":
                "A05:2021 Security Misconfiguration",


                "description":
                str(e),


                "recommendation":
                "Check website URL."

            }],


            "scanner_version":
            "CyberSentinel v2.1",


            "scan_time":
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            ),


            "scan_status":
            "Failed"

        }