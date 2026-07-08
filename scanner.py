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

    # Fix user typing mistakes
    url = url.replace(
        "w.w.w.",
        "www."
    )

    url = url.replace(
        "WWW.",
        "www."
    )


    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url


    return url



# ---------------------------------
# Get IP Address
# ---------------------------------

def get_ip(domain):

    try:
        return socket.gethostbyname(domain)

    except:
        return "Unknown"



# ---------------------------------
# SSL Certificate Check
# ---------------------------------

def check_ssl(domain):

    ssl_data = {

        "status": "Failed",
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


                cert = ssock.getpeercert()


                expiry = cert.get(
                    "notAfter"
                )


                if expiry:

                    expiry_date = datetime.strptime(
                        expiry,
                        "%b %d %H:%M:%S %Y %Z"
                    )


                    ssl_data["expiry"] = str(
                        expiry_date.date()
                    )


                    ssl_data["days_remaining"] = (
                        expiry_date -
                        datetime.utcnow()
                    ).days



                ssl_data["status"] = "Valid"


                ssl_data["issuer"] = dict(
                    x[0]
                    for x in cert["issuer"]
                ).get(
                    "organizationName",
                    "Unknown"
                )



    except:

        pass



    return ssl_data




# ---------------------------------
# Port Scanner
# ---------------------------------

def check_open_ports(domain):

    open_ports=[]


    for port,service in COMMON_PORTS.items():

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )


            sock.settimeout(0.5)


            result = sock.connect_ex(
                (domain,port)
            )


            if result == 0:

                open_ports.append({

                    "port":port,

                    "service":service

                })


            sock.close()


        except:

            pass


    return open_ports




# ---------------------------------
# Technology Detection
# ---------------------------------

def detect_technology(headers):

    tech=[]


    data = (

        headers.get("Server","")
        +
        headers.get("X-Powered-By","")

    ).lower()



    technologies={

        "nginx":"Nginx",

        "apache":"Apache",

        "cloudflare":"Cloudflare",

        "php":"PHP",

        "wordpress":"WordPress",

        "react":"React"

    }



    for key,value in technologies.items():

        if key in data:

            tech.append(value)



    if not tech:

        tech.append(
            "Not Disclosed"
        )


    return tech




# ---------------------------------
# Security Header Scanner
# ---------------------------------

def analyze_headers(headers):

    findings=[]


    checks={


        "Content-Security-Policy":(
            "Missing Content Security Policy",
            "Medium",
            5.3,
            "A05:2021 Security Misconfiguration"
        ),


        "Strict-Transport-Security":(
            "Missing HTTPS Security Policy",
            "Medium",
            5.3,
            "A02:2021 Cryptographic Failures"
        ),


        "X-Frame-Options":(
            "Missing Clickjacking Protection",
            "Medium",
            4.7,
            "A05:2021 Security Misconfiguration"
        ),


        "X-Content-Type-Options":(
            "Missing MIME Protection",
            "Low",
            3.1,
            "A05:2021 Security Misconfiguration"
        ),


        "Referrer-Policy":(
            "Missing Referrer Policy",
            "Low",
            3.1,
            "A05:2021 Security Misconfiguration"
        )

    }



    for header,data in checks.items():


        if header not in headers:


            findings.append({

                "title":data[0],

                "name":data[0],

                "severity":data[1],

                "cvss":data[2],

                "owasp":data[3],

                "simple_explanation":data[0],

                "technical_explanation":
                "Security header is missing.",

                "description":
                f"{header} header was not detected.",

                "business_impact":
                "May increase website attack surface.",

                "recommendation":
                f"Enable {header} security header."

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

                "description":
                cookie.name,

                "recommendation":
                "Enable Secure attribute."

            })


    return findings




# ---------------------------------
# Main Website Scanner
# ---------------------------------

def scan_website(url):

    try:


        url = normalize_url(url)


        parsed=urlparse(url)


        domain=parsed.netloc



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



        return {


            "url":
            response.url,


            "ip":
            get_ip(domain),


            "ssl":
            check_ssl(domain),


            "headers":
            headers,


            "ports":
            check_open_ports(domain),


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

            "server":
            "Unknown",


            "http_status":
            "Unknown",


            "response_time":
            0,


            "findings":[{


                "title":
                "Scan Failed",

                "name":
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