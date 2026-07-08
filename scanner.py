# ---------------------------------
# CyberSentinel v2.1
# Professional Website Security Scanner
# ---------------------------------

import socket
import requests
import time
import ssl

from datetime import datetime

from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend



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
        ("http://","https://")
    ):

        url = "https://" + url


    return url





# ---------------------------------
# SSL CERTIFICATE CHECK
# ---------------------------------

def check_ssl_certificate(domain):

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


                cert = ssock.getpeercert(
                    binary_form=True
                )


                certificate = x509.load_der_x509_certificate(
                    cert,
                    default_backend()
                )


                expiry = certificate.not_valid_after


                issuer = certificate.issuer.rfc4514_string()



                days = (
                    expiry -
                    datetime.utcnow()
                ).days



                return {

                    "status":"Valid",

                    "issuer":issuer,

                    "expiry":
                    expiry.strftime(
                        "%Y-%m-%d"
                    ),

                    "days_remaining":
                    days

                }


    except Exception:


        return {

            "status":"Failed",

            "issuer":"",

            "expiry":"",

            "days_remaining":0

        }






# ---------------------------------
# PORT SCANNER
# ---------------------------------

def check_open_ports(domain):

    ports=[]


    for port in COMMON_PORTS:


        try:

            sock=socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(
                0.5
            )


            result=sock.connect_ex(
                (
                    domain,
                    port
                )
            )


            if result==0:


                service="Unknown"


                if port==80:
                    service="HTTP"


                elif port==443:
                    service="HTTPS"



                ports.append({

                    "port":port,

                    "service":service

                })


            sock.close()



        except:

            pass



    return ports





# ---------------------------------
# SECURITY HEADER CHECK
# ---------------------------------

def analyze_headers(headers):


    findings=[]


    checks={


        "Content-Security-Policy":{

            "name":
            "Missing Content Security Policy",

            "cvss":5.3,

            "severity":"Medium",

            "owasp":
            "A05:2021 - Security Misconfiguration",

            "component":
            "HTTP Security Headers",

            "impact":
            "Missing CSP may increase exposure to script injection attacks.",

            "fix":
            "Enable Content-Security-Policy security header."

        },



        "Strict-Transport-Security":{

            "name":
            "Missing HTTPS Security Policy",

            "cvss":5.3,

            "severity":"Medium",

            "owasp":
            "A05:2021 - Security Misconfiguration",

            "component":
            "HTTPS Configuration",

            "impact":
            "Without HSTS users may be exposed to downgrade attacks.",

            "fix":
            "Enable Strict-Transport-Security header."

        },



        "X-Content-Type-Options":{

            "name":
            "Missing MIME Protection",

            "cvss":3.1,

            "severity":"Low",

            "owasp":
            "A05:2021 - Security Misconfiguration",

            "component":
            "HTTP Security Headers",

            "impact":
            "Missing MIME protection may increase browser attack risks.",

            "fix":
            "Enable X-Content-Type-Options header."

        },



        "Referrer-Policy":{

            "name":
            "Missing Referrer Policy",

            "cvss":3.1,

            "severity":"Low",

            "owasp":
            "A05:2021 - Security Misconfiguration",

            "component":
            "HTTP Security Headers",

            "impact":
            "Sensitive referrer information may be exposed.",

            "fix":
            "Enable Referrer-Policy header."

        }

    }





    for header,data in checks.items():


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
                data["impact"],

                "business_impact":
                data["impact"],

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

    findings=[]


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
                "A05:2021 - Security Misconfiguration",

                "affected_component":
                "Browser Cookies",

                "impact":
                "Improper cookie protection may expose session information.",

                "description":
                cookie.name,

                "recommendation":
                "Enable Secure cookie attribute."

            })



    return findings





# ---------------------------------
# MAIN SCANNER
# ---------------------------------

def scan_website(url):


    try:


        url=normalize_url(
            url
        )



        start=time.time()



        response=requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={

                "User-Agent":
                "Mozilla/5.0 CyberSentinel Security Scanner"

            }

        )



        response_time=round(

            (
                time.time()-start
            )*1000,

            2

        )



        parsed=urlparse(
            response.url
        )


        domain=parsed.netloc



        ip=socket.gethostbyname(
            domain
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



        return {


            "url":
            response.url,


            "ip":
            ip,


            "headers":
            headers,


            "ssl":
            check_ssl_certificate(
                domain
            ),


            "ports":
            check_open_ports(
                domain
            ),


            "http_status":
            response.status_code,


            "server":
            headers.get(
                "Server",
                "Unknown"
            ),


            "technology":
            headers.get(
                "X-Powered-By",
                "Not Disclosed"
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


            "ssl":
            {
                "status":"Failed"
            },


            "ports":
            [],


            "http_status":
            "Unavailable",


            "server":
            "Unknown",


            "technology":
            "Unknown",


            "response_time":
            0,


            "findings":[{

                "name":
                "Scan Failed",

                "cvss":
                0,

                "severity":
                "INFO",

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