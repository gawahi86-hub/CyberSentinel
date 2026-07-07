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

        "Content-Security-Policy":
        "Missing Content Security Policy",

        "Strict-Transport-Security":
        "Missing HTTPS Security Policy",

        "X-Frame-Options":
        "Missing Clickjacking Protection",

        "X-Content-Type-Options":
        "Missing MIME Protection"

    }


    for header, message in security_headers.items():

        if header not in headers:

            findings.append({

                "title": message,

                "severity": "Medium",

                "cvss": 5.3,

                "description":
                f"{header} header is missing",

                "recommendation":
                f"Implement {header} security header"

            })


    return findings




# ---------------------------------
# Cookie Security Check
# ---------------------------------

def analyze_cookies(cookies):

    findings=[]


    for cookie in cookies:


        if not cookie.secure:

            findings.append({

                "title":
                "Cookie Missing Secure Flag",

                "severity":
                "Low",

                "cvss":
                3.1,

                "description":
                f"Cookie {cookie.name} is not secured",

                "recommendation":
                "Enable Secure cookie attribute"

            })


        if "httponly" not in cookie._rest:

            findings.append({

                "title":
                "Cookie Missing HttpOnly Flag",

                "severity":
                "Medium",

                "cvss":
                4.7,

                "description":
                f"Cookie {cookie.name} may be accessible through scripts",

                "recommendation":
                "Enable HttpOnly flag"

            })


    return findings





# ---------------------------------
# Main Website Scanner
# ---------------------------------

def scan_website(url):

    try:


        if not url.startswith("http"):
            url="https://" + url


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


        # IP Detection

        try:

            ip=socket.gethostbyname(domain)

        except:

            ip="Unknown"



        headers=dict(response.headers)



        findings=[]


        # Header Scan

        findings.extend(
            analyze_headers(headers)
        )



        # Cookie Scan

        findings.extend(
            analyze_cookies(
                response.cookies
            )
        )



        # Port Scan

        ports=check_open_ports(domain)



        # Open port risks

        if 21 in ports:

            findings.append({

                "title":
                "FTP Port Open",

                "severity":
                "High",

                "cvss":
                7.5,

                "description":
                "FTP service detected",

                "recommendation":
                "Disable FTP and use SFTP"

            })



        return {


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


            "risk_score":
            len(findings) * 10


        }



    except Exception as e:


        return {


            "ip":
            "Unknown",


            "headers":
            {},


            "ssl":
            False,


            "ports":
            [],


            "http_status":
            0,


            "response_time":
            0,


            "server":
            "Unknown",


            "technology":
            "Unknown",


            "cookies":
            [],


            "findings":[{


                "title":
                "Scanner Error",

                "severity":
                "Info",

                "cvss":
                0,

                "description":
                str(e),

                "recommendation":
                "Check URL and connectivity"

            }],


            "risk_score":
            0

        }