# ---------------------------------
# CyberSentinel v2.1
# Professional Website Security Scanner
# ---------------------------------

import socket
import requests
import time

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

    url=url.strip()

    url=url.replace(
        " ",
        ""
    )


    if not url.startswith(
        ("http://","https://")
    ):

        url="https://" + url


    return url





# ---------------------------------
# PORT SCANNER
# ---------------------------------

def check_open_ports(domain):

    open_ports=[]


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
                (domain,port)
            )


            if result==0:

                service="Unknown"


                if port==80:
                    service="HTTP"

                elif port==443:
                    service="HTTPS"


                open_ports.append({

                    "port":port,

                    "service":service

                })


            sock.close()



        except:

            pass



    return open_ports






# ---------------------------------
# SECURITY HEADER ANALYSIS
# ---------------------------------

def analyze_headers(headers):


    findings=[]



    security_headers={


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
            "Without HSTS, users may be exposed to downgrade attacks.",


            "fix":
            "Enable Strict-Transport-Security security header."

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
            "Missing MIME protection may allow browser interpretation attacks.",


            "fix":
            "Enable X-Content-Type-Options security header."

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
            "Referrer information may leak unnecessarily.",


            "fix":
            "Enable Referrer-Policy security header."

        }

    }




    for header,data in security_headers.items():


        if header not in headers:


            findings.append({


                "name":
                data["name"],


                "title":
                data["name"],


                "severity":
                data["severity"],


                "cvss":
                data["cvss"],


                "owasp":
                data["owasp"],


                "affected_component":
                data["component"],


                "impact":
                data["impact"],


                "business_impact":
                data["impact"],


                "simple_explanation":
                data["name"],


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


                "title":
                "Cookie Missing Secure Flag",


                "severity":
                "Low",


                "cvss":
                3.1,


                "owasp":
                "A05:2021 - Security Misconfiguration",


                "affected_component":
                "Browser Cookies",


                "impact":
                "Improper cookie protection may expose session information.",


                "business_impact":
                "Improper cookie protection may expose session information.",


                "simple_explanation":
                cookie.name,


                "description":
                cookie.name,


                "technical_explanation":
                "Cookie is missing Secure attribute.",


                "recommendation":
                "Enable Secure cookie attribute."

            })



    return findings






# ---------------------------------
# SSL CHECK
# ---------------------------------

def ssl_status(url):


    if url.startswith(
        "https"
    ):

        return {

            "status":
            "Valid"

        }


    return {

        "status":
        "Not Secure"

    }







# ---------------------------------
# MAIN SCANNER
# ---------------------------------

def scan_website(url):


    try:


        url=normalize_url(url)



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



        parsed=urlparse(
            response.url
        )



        domain=parsed.netloc



        try:

            ip=socket.gethostbyname(
                domain
            )


        except:

            ip="Unknown"




        headers=dict(
            response.headers
        )



        findings=[]



        findings.extend(

            analyze_headers(
                headers
            )

        )



        findings.extend(

            analyze_cookies(
                response.cookies
            )

        )



        ports=check_open_ports(
            domain
        )



        return {


            "url":
            response.url,


            "ip":
            ip,


            "headers":
            headers,


            "ssl":
            ssl_status(
                response.url
            ),


            "ports":
            ports,


            "http_status":
            response.status_code,


            "response_time":
            response_time,


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



            "cookies":
            list(
                response.cookies
            ),



            "findings":
            findings,



            # NEW

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


            "headers":{},


            "ssl":
            {

                "status":
                "Failed"

            },


            "ports":[],


            "http_status":
            "Unavailable",


            "response_time":
            0,


            "server":
            "Unknown",


            "technology":
            "Unknown",



            "findings":[{


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



            "scanner_version":
            "CyberSentinel v2.1",



            "scan_time":
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            ),



            "scan_status":
            "Failed"

        }