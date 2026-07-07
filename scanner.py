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
            "Your website is missing an additional browser safety setting that helps block harmful scripts.",

            "impact":
            "Attackers may have a better chance of injecting unwanted scripts into website pages.",

            "technical":
            "The Content-Security-Policy header reduces the impact of Cross-Site Scripting attacks.",

            "fix":
            "Implement a Content-Security-Policy security header."

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
            "Users may be exposed to downgrade or insecure connection risks.",

            "technical":
            "HTTP Strict Transport Security (HSTS) instructs browsers to use HTTPS only.",

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
            "Attackers may attempt to trick users into clicking hidden website elements.",

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
            "Your website is missing an extra protection that helps browsers handle files safely.",

            "impact":
            "Certain browser-based attacks may become easier to perform.",

            "technical":
            "X-Content-Type-Options prevents MIME type sniffing attacks.",

            "fix":
            "Enable X-Content-Type-Options header."

        }

    }



    for header, data in security_headers.items():

        if header not in headers:

            findings.append({

                "title":
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
# Cookie Security Check
# ---------------------------------

def analyze_cookies(cookies):

    findings = []


    for cookie in cookies:


        if not cookie.secure:

            findings.append({

                "title":
                "Cookie Missing Secure Flag",

                "severity":
                "Low",

                "cvss":
                3.1,

                "simple_explanation":
                "A website cookie is not marked as secure.",

                "business_impact":
                "A poorly protected cookie could increase the risk of account session exposure.",

                "technical_explanation":
                "Cookies without the Secure attribute may be transmitted over insecure connections.",

                "description":
                f"Cookie {cookie.name} is not secured.",

                "recommendation":
                "Enable Secure cookie attribute."

            })



        if "httponly" not in cookie._rest:


            findings.append({

                "title":
                "Cookie Missing HttpOnly Flag",

                "severity":
                "Medium",

                "cvss":
                4.7,

                "simple_explanation":
                "A website cookie may be readable by browser scripts.",

                "business_impact":
                "This could increase the impact of certain browser-based attacks.",

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

    url = url.strip()

    url = url.replace(
        " ",
        ""
    )


    if url.startswith("w.w.w."):

        url = url.replace(
            "w.w.w.",
            "www.",
            1
        )


    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url


    return url





# ---------------------------------
# Main Scanner
# ---------------------------------

def scan_website(url):

    try:


        url = normalize_url(url)


        parsed = urlparse(url)

        domain = parsed.netloc



        response_start = time.time()



        response = requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={

                "User-Agent":
                "CyberSentinel Security Scanner"

            }

        )


        response_time = round(

            (time.time()-response_start)*1000,

            2

        )


        try:

            ip = socket.gethostbyname(domain)

        except:

            ip="Unknown"



        headers = dict(
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



        ports = check_open_ports(domain)



        if 21 in ports:

            findings.append({

                "title":
                "FTP Port Open",

                "severity":
                "High",

                "cvss":
                7.5,

                "simple_explanation":
                "An old file transfer service is publicly available.",

                "business_impact":
                "Attackers may attempt unauthorized access or data theft.",

                "technical_explanation":
                "FTP transmits credentials without modern encryption.",

                "description":
                "FTP service detected.",

                "recommendation":
                "Disable FTP and use SFTP."

            })



        return {


            "url":
            url,

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
            len(findings) * 10,

            "scan_status":
            "Success"

        }



    except requests.exceptions.RequestException:


        return {

            "findings":[{

                "title":
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
                "Website unreachable or invalid URL.",

                "recommendation":
                "Verify the website address."

            }],

            "risk_score":
            0,

            "scan_status":
            "Failed"

        }