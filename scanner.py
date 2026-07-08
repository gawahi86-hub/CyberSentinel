import socket
import requests
import time

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
# Port Scanner
# ---------------------------------

def check_open_ports(domain):

    open_ports = []

    for port in COMMON_PORTS:

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
                open_ports.append(port)

            sock.close()


        except:

            pass


    return open_ports





# ---------------------------------
# Security Header Analysis
# ---------------------------------

def analyze_headers(headers):

    findings = []


    security_headers = {


        "Content-Security-Policy": {

            "title":
            "Missing Content Security Policy",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "simple":
            "Your website is missing an extra browser security setting that helps block harmful scripts.",

            "impact":
            "Attackers may have a higher chance of injecting unwanted scripts into website pages.",

            "technical":
            "Content-Security-Policy reduces the impact of Cross-Site Scripting attacks.",

            "fix":
            "Implement Content-Security-Policy security header."

        },



        "Strict-Transport-Security": {


            "title":
            "Missing HTTPS Security Policy",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "simple":
            "Your website does not force browsers to always use secure HTTPS connections.",

            "impact":
            "Users may be exposed to insecure connection downgrade attacks.",

            "technical":
            "HSTS instructs browsers to use HTTPS only.",

            "fix":
            "Enable Strict-Transport-Security header."

        },



        "X-Frame-Options": {


            "title":
            "Missing Clickjacking Protection",

            "cvss":
            4.7,

            "severity":
            "Medium",

            "simple":
            "Your website has limited protection against being displayed inside another website.",

            "impact":
            "Attackers may trick users into clicking hidden elements.",

            "technical":
            "X-Frame-Options prevents unauthorized iframe embedding.",

            "fix":
            "Enable X-Frame-Options: DENY or SAMEORIGIN."

        },



        "X-Content-Type-Options": {


            "title":
            "Missing MIME Protection",

            "cvss":
            4.7,

            "severity":
            "Medium",

            "simple":
            "Your website is missing browser file protection settings.",

            "impact":
            "Some browser attacks may become easier.",

            "technical":
            "X-Content-Type-Options prevents MIME sniffing attacks.",

            "fix":
            "Enable X-Content-Type-Options header."

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


                "simple_explanation":
                data["simple"],


                "business_impact":
                data["impact"],


                "technical_explanation":
                data["technical"],


                "description":
                data["technical"],


                "recommendation":
                data["fix"]

            })


    return findings






# ---------------------------------
# Cookie Analysis
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


                "simple_explanation":
                "A website cookie is not marked as secure.",


                "business_impact":
                "Session information may have increased exposure risk.",


                "technical_explanation":
                "Cookies without Secure attribute may be transmitted insecurely.",


                "description":
                f"Cookie {cookie.name} is not secured.",


                "recommendation":
                "Enable Secure cookie attribute."

            })



        if "httponly" not in cookie._rest:


            findings.append({

                "title":
                "Cookie Missing HttpOnly Flag",

                "name":
                "Cookie Missing HttpOnly Flag",

                "severity":
                "Medium",

                "cvss":
                4.7,


                "simple_explanation":
                "A browser script may be able to access this cookie.",


                "business_impact":
                "This can increase the impact of browser attacks.",


                "technical_explanation":
                "HttpOnly prevents JavaScript access to sensitive cookies.",


                "description":
                f"Cookie {cookie.name} may be accessible through scripts.",


                "recommendation":
                "Enable HttpOnly flag."

            })


    return findings





# ---------------------------------
# URL Normalization
# ---------------------------------

def normalize_url(url):


    url=url.strip()


    url=url.replace(
        " ",
        ""
    )



    clean=url.replace(
        "https://",
        ""
    ).replace(
        "http://",
        ""
    )



    if clean.startswith(
        "w.w.w."
    ):

        clean=clean.replace(
            "w.w.w.",
            "www.",
            1
        )



    return "https://" + clean






# ---------------------------------
# Main Scanner
# ---------------------------------

def scan_website(url):


    try:


        url=normalize_url(url)


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



        try:

            ip=socket.gethostbyname(domain)


        except:

            ip="Unknown"




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




        ports=check_open_ports(
            domain
        )





        if 21 in ports:


            findings.append({

                "title":
                "FTP Port Open",

                "name":
                "FTP Port Open",

                "severity":
                "High",

                "cvss":
                7.5,


                "simple_explanation":
                "An old file transfer service is publicly available.",


                "business_impact":
                "Attackers may attempt unauthorized access.",


                "technical_explanation":
                "FTP does not provide modern encryption protection.",


                "description":
                "FTP service detected.",


                "recommendation":
                "Disable FTP and use SFTP."

            })




        return {


            "url":
            response.url,


            "ip":
            ip,


            "headers":
            headers,


            "ssl":
            response.url.startswith(
                "https"
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
            list(response.cookies),


            "findings":
            findings,


            # Risk engine calculates this

            "risk_score":
            0,


            "scan_status":
            "Success"

        }





    except requests.exceptions.RequestException as e:



        return {


            "url":
            url,


            "ip":
            "Unknown",


            "headers":
            {},


            "ssl":
            False,


            "ports":
            [],


            "http_status":
            "Unavailable",


            "response_time":
            0,


            "server":
            "Unknown",


            "technology":
            "Unknown",



            "findings":[{


                "title":
                "Scan Failed",


                "name":
                "Scan Failed",


                "severity":
                "INFO",


                "cvss":
                0,


                "simple_explanation":
                "The website could not be checked.",


                "business_impact":
                "No security conclusion can be made until the website is reachable.",


                "technical_explanation":
                "The scanner could not establish a connection.",


                "description":
                str(e),


                "recommendation":
                "Verify the website address."

            }],



            "risk_score":
            0,


            "scan_status":
            "Failed"

        }