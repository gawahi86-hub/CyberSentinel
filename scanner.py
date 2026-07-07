import socket
import requests
import time

from urllib.parse import urlparse


# ==================================================
# CyberSentinel Security Scanner
# Version: Final SOC Edition
# ==================================================


COMMON_PORTS = [
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    53,      # DNS
    80,      # HTTP
    110,     # POP3
    143,     # IMAP
    443,     # HTTPS
    3306,    # MySQL
    8080     # Web Proxy
]



# ==================================================
# PORT SCANNER
# ==================================================

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


        except Exception:

            pass



    return open_ports





# ==================================================
# SECURITY FINDING BUILDER
# ==================================================

def create_finding(
        title,
        severity,
        cvss,
        simple,
        impact,
        technical,
        recommendation
):

    return {

        "title": title,

        "name": title,

        "severity": severity,

        "cvss": cvss,


        "simple_explanation": simple,


        "business_impact": impact,


        "technical_explanation": technical,


        "description": technical,


        "recommendation": recommendation

    }





# ==================================================
# SECURITY HEADER ANALYSIS
# ==================================================

def analyze_headers(headers):

    findings = []



    security_headers = {


        "Content-Security-Policy": {


            "title":
            "Missing Content Security Policy",


            "severity":
            "Medium",


            "cvss":
            5.3,


            "simple":
            "The website does not have a browser policy that helps prevent malicious scripts.",


            "impact":
            "Attackers may have a higher chance of performing Cross-Site Scripting attacks.",


            "technical":
            "Content-Security-Policy controls which scripts and resources browsers are allowed to load.",


            "fix":
            "Implement a suitable Content-Security-Policy header."

        },



        "Strict-Transport-Security": {


            "title":
            "Missing HTTP Strict Transport Security",


            "severity":
            "Medium",


            "cvss":
            5.3,


            "simple":
            "The website does not force browsers to always use HTTPS.",


            "impact":
            "Users may be exposed to downgrade or insecure connection attacks.",


            "technical":
            "HSTS forces browsers to communicate only through encrypted HTTPS connections.",


            "fix":
            "Enable Strict-Transport-Security header."

        },



        "X-Frame-Options": {


            "title":
            "Missing Clickjacking Protection",


            "severity":
            "Medium",


            "cvss":
            4.7,


            "simple":
            "The website may be displayed inside another malicious website.",


            "impact":
            "Attackers may trick users into unwanted clicks.",


            "technical":
            "X-Frame-Options prevents unauthorized iframe embedding.",


            "fix":
            "Set X-Frame-Options to DENY or SAMEORIGIN."

        },



        "X-Content-Type-Options": {


            "title":
            "Missing MIME Type Protection",


            "severity":
            "Low",


            "cvss":
            3.7,


            "simple":
            "The website does not prevent browsers from guessing file types.",


            "impact":
            "Some browser-based attacks may become easier.",


            "technical":
            "X-Content-Type-Options prevents MIME sniffing attacks.",


            "fix":
            "Enable X-Content-Type-Options: nosniff."

        },


        "Referrer-Policy": {


            "title":
            "Missing Referrer Policy",


            "severity":
            "Low",


            "cvss":
            3.1,


            "simple":
            "The website may reveal extra browsing information when users visit other websites.",


            "impact":
            "Sensitive URL information may be leaked.",


            "technical":
            "Referrer-Policy controls browser referrer information sharing.",


            "fix":
            "Implement a secure Referrer-Policy header."

        }

    }



    for header, data in security_headers.items():


        if header not in headers:


            findings.append(

                create_finding(

                    data["title"],

                    data["severity"],

                    data["cvss"],

                    data["simple"],

                    data["impact"],

                    data["technical"],

                    data["fix"]

                )

            )



    return findings
# ==================================================
# COOKIE SECURITY ANALYSIS
# ==================================================

def analyze_cookies(cookies):

    findings = []


    for cookie in cookies:


        # Secure flag check

        if not cookie.secure:


            findings.append(

                create_finding(

                    "Cookie Missing Secure Flag",

                    "Low",

                    3.1,

                    "A website cookie is not marked as secure.",

                    "Session information may have increased exposure risk if transmitted without encryption.",

                    "The Secure attribute ensures cookies are only sent through HTTPS connections.",

                    "Enable the Secure attribute for all sensitive cookies."

                )

            )



        # HttpOnly check

        httponly = False


        try:

            for item in cookie._rest:

                if "httponly" in item.lower():

                    httponly = True


        except Exception:

            pass



        if not httponly:


            findings.append(

                create_finding(

                    "Cookie Missing HttpOnly Flag",

                    "Medium",

                    4.7,

                    "Browser scripts may be able to access website cookies.",

                    "This may increase the impact of Cross-Site Scripting attacks.",

                    "HttpOnly prevents JavaScript from accessing sensitive cookies.",

                    "Enable HttpOnly attribute on authentication cookies."

                )

            )



    return findings





# ==================================================
# URL NORMALIZATION
# ==================================================

def normalize_url(url):


    url = url.strip()



    url = url.replace(
        " ",
        ""
    )



    if not url.startswith(
        "http://"
    ) and not url.startswith(
        "https://"
    ):

        url = "https://" + url



    return url





# ==================================================
# RISK ENGINE
# ==================================================

def calculate_risk_score(findings):


    if not findings:

        return 0



    score = 0



    for finding in findings:


        score += float(

            finding.get(
                "cvss",
                0
            )

        )



    return min(

        round(score, 1),

        100

    )





# ==================================================
# SECURITY GRADE
# ==================================================

def calculate_grade(score):


    if score <= 20:

        return "A"


    elif score <= 40:

        return "B"


    elif score <= 60:

        return "C"


    elif score <= 80:

        return "D"


    else:

        return "F"







# ==================================================
# RISK CLASSIFICATION
# ==================================================

def classify_risk(score):


    if score <= 20:


        return {

            "level":
            "LOW",


            "verdict":
            "SAFE",


            "summary":
            "The website demonstrates a strong security posture with limited security concerns."

        }



    elif score <= 50:


        return {


            "level":
            "MEDIUM",


            "verdict":
            "MODERATE RISK",


            "summary":
            "Some security weaknesses were identified. Recommended improvements should be applied."

        }



    elif score <= 80:


        return {


            "level":
            "HIGH",


            "verdict":
            "HIGH RISK",


            "summary":
            "Multiple security issues were detected. Immediate security improvements are recommended."

        }



    else:


        return {


            "level":
            "CRITICAL",


            "verdict":
            "CRITICAL RISK",


            "summary":
            "Critical security weaknesses were detected. Immediate security review is required."

        }





# ==================================================
# PORT RISK ANALYSIS
# ==================================================

def analyze_ports(ports):


    findings = []



    risky_ports = {


        21:
        (
            "FTP Port Exposed",
            "High",
            7.5,
            "An outdated file transfer service is publicly accessible.",
            "Attackers may attempt unauthorized access or data interception.",
            "FTP transfers data without modern encryption protection.",
            "Disable FTP and use secure alternatives such as SFTP."
        ),



        23:
        (
            "Telnet Port Exposed",
            "Critical",
            9.0,
            "An insecure remote access service is publicly available.",
            "Attackers may capture login information.",
            "Telnet transmits credentials without encryption.",
            "Disable Telnet and use SSH."
        )

    }



    for port in ports:


        if port in risky_ports:


            data = risky_ports[port]


            findings.append(

                create_finding(

                    data[0],
                    data[1],
                    data[2],
                    data[3],
                    data[4],
                    data[5],
                    data[6]

                )

            )



    return findings
# ==================================================
# MAIN WEBSITE SCANNER
# ==================================================

def scan_website(url):


    try:


        # Normalize URL

        url = normalize_url(
            url
        )



        parsed = urlparse(
            url
        )



        domain = parsed.netloc



        start_time = time.time()



        # Website request

        response = requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={

                "User-Agent":
                "CyberSentinel-SOC-Scanner"

            }

        )



        response_time = round(

            (time.time() - start_time) * 1000,

            2

        )





        # IP Resolution

        try:


            ip_address = socket.gethostbyname(

                domain

            )


        except Exception:


            ip_address = "Unknown"







        # Collect headers

        headers = dict(

            response.headers

        )





        findings = []





        # Header Security Scan

        findings.extend(

            analyze_headers(

                headers

            )

        )





        # Cookie Security Scan

        findings.extend(

            analyze_cookies(

                response.cookies

            )

        )





        # Port Scan

        open_ports = check_open_ports(

            domain

        )





        # Port Vulnerability Scan

        findings.extend(

            analyze_ports(

                open_ports

            )

        )






        # Calculate Risk

        risk_score = calculate_risk_score(

            findings

        )



        risk = classify_risk(

            risk_score

        )



        grade = calculate_grade(

            risk_score

        )







        return {


            "url":

            response.url,



            "domain":

            domain,



            "ip":

            ip_address,



            "headers":

            headers,



            "ssl":

            response.url.startswith(

                "https"

            ),



            "ports":

            open_ports,



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





            "risk_score":

            risk_score,





            "risk_level":

            risk["level"],





            "security_grade":

            grade,





            "safety_verdict":

            risk["verdict"],





            "final_summary":

            risk["summary"],





            "scan_status":

            "Success"

        }





    except requests.exceptions.RequestException as error:





        return {


            "url":

            url,



            "domain":

            "Unknown",



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



            "cookies":

            [],



            "findings": [


                create_finding(

                    "Website Scan Failed",

                    "INFO",

                    0,

                    "The website could not be scanned.",

                    "A security assessment could not be completed.",

                    str(error),

                    "Verify the website address and ensure it is reachable."

                )

            ],



            "risk_score":

            0,



            "risk_level":

            "UNKNOWN",



            "security_grade":

            "N/A",



            "safety_verdict":

            "SCAN FAILED",



            "final_summary":

            "The scanner was unable to complete the security assessment.",



            "scan_status":

            "Failed"

        }
    # ==================================================
# SCAN SUMMARY GENERATOR
# ==================================================

def generate_scan_summary(findings):


    summary = {


        "total":

        len(findings),


        "critical":

        0,


        "high":

        0,


        "medium":

        0,


        "low":

        0

    }




    for finding in findings:


        severity = finding.get(

            "severity",

            ""

        ).upper()



        if severity == "CRITICAL":

            summary["critical"] += 1



        elif severity == "HIGH":

            summary["high"] += 1



        elif severity == "MEDIUM":

            summary["medium"] += 1



        elif severity == "LOW":

            summary["low"] += 1





    return summary





# ==================================================
# TEST MODE
# ==================================================

if __name__ == "__main__":


    print(

        """

        =================================

        CyberSentinel Security Scanner

        Test Mode

        =================================

        """

    )



    target = input(

        "Enter website URL: "

    )



    result = scan_website(

        target

    )



    print("\nWebsite:")

    print(

        result.get(

            "url"

        )

    )



    print("\nRisk Score:")

    print(

        result.get(

            "risk_score"

        )

    )



    print("\nSecurity Grade:")

    print(

        result.get(

            "security_grade"

        )

    )



    print("\nRisk Level:")

    print(

        result.get(

            "risk_level"

        )

    )



    print("\nVerdict:")

    print(

        result.get(

            "safety_verdict"

        )

    )



    print("\nFindings:")


    for item in result.get(

        "findings",

        []

    ):


        print(

            "-",

            item.get(

                "name"

            ),

            "| CVSS:",

            item.get(

                "cvss"

            )

        )
