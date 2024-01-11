import requests
import json
from datetime import datetime
import urllib3
import argparse
import os
import re

import sys
from threading import Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
VER 1.1.1
"""

version = "1.1.1"

changeLog = """
CHANGE LOG
== VER 1.1
- Changed the code's base, added functions etc,
- Added Threads,
- Removed .txt output,
- Fixed issue in HTML file for domain links not present in VirusTotal,
== VER 1.1.1
- Fixed issues in HTML file for AbuseIPDB reporting,
- Added a text when a report is generated at the end of cli output.
"""

print(r"""                                          
 ____                        _        ____ _               _         
|  _ \  ___  _ __ ___   __ _(_)_ __  / ___| |__   ___  ___| | ___ __ 
| | | |/ _ \| '_ ` _ \ / _` | | '_ \| |   | '_ \ / _ \/ __| |/ / '__|
| |_| | (_) | | | | | | (_| | | | | | |___| | | |  __/ (__|   <| |   
|____/ \___/|_| |_| |_|\__,_|_|_| |_|\____|_| |_|\___|\___|_|\_\_|   
                                        
                                                    Version 1.0                                    
                                               
""")

argParser = argparse.ArgumentParser(prog='DomainCheckr.py',
                    description='Analyze IP Addresses and domains using Virus Total and Abuse IPDB APIs.',
                    epilog='''If you wont input anything, the code will run using the target-list.txt using VirusTotal and AbuseIPDB.
                      You can input domains but they will be only checked on Virus Total because Abuse API does not support domains.''')
argParser.add_argument("-V", "--version", action="store_true", help="Prints current version of the script and exit.", required=False)
argParser.add_argument("-i", "--input", type=str, help="To check single value.", required=False, metavar="[Value]")
argParser.add_argument("-r", "--report", action="store_true", help="Generate HTML report.", required=False)
argParser.add_argument("-vt","--virustotal", action="store_true", help="Disable virustotal", required=False)
argParser.add_argument("-a", "--abuse", action="store_true", help="Disable AbuseIPDB", required=False)
argParser.add_argument("-vr","--virustotalreports", type=int, help="Virustotal malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshold number]")
argParser.add_argument("-ar","--abusereports", type=int, help="Abuse IP DB malicious reports threshold. Default 1.", required=False, default=1, metavar="[Threshold number]")
argParser.add_argument("-p", "--path", type=str, help="Provide path of the txt file contains targets. Default 'target-list.txt'.", required=False, default="target-list.txt")
argParser.add_argument("-t", "--threads", type=int, help="Use multiple threads. It is recommended to use it if you have licenced API keys. Also cli output is buggy when used. I recommend using it with -r.", required=False, default=1, metavar="[Threads]")
argParser.add_argument("-w", "--whois", action="store_true", help="Run whois analysis on the provided targets.", required=False)



args = argParser.parse_args()

# INIT GLOBAL PARAMS
htmlReport = []
maliciousValues = []
totalCounter = 0 
successfullyChecked= 0
failedValues = []

if args.version:
    print(f"Current version is {version}")
    print(changeLog)
    exit()

if args.report:
    print("What do you want to call the 'report' HTML file?:")
    reportName = input() + ".html"


ipPattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

if args.whois:
 
 import requests

 def extract_domains_from_requirements(file_path):
    domains = []
    with open(file_path, 'r') as file:
        for line in file:
            # Assuming the domains are listed in the format "domain==version"
            package_name = line.strip().split('==')[0]
            domains.append(f"{package_name}")  # Append ".com" for simplicity, you may need a more accurate method
    return domains

 def check_domain_info(api_key, domains):
    api_endpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    results = []

    for domain in domains:
        api_url = f"{api_endpoint}?apiKey={api_key}&domainName={domain}&outputFormat=JSON"

        try:
            response = requests.get(api_url)
            data = response.json()

            if response.status_code == 200 and data.get("WhoisRecord", {}).get("registryData"):
                registry_data = data["WhoisRecord"]["registryData"]

                result = {
                    "domain": domain,
                    "whois_data": {
                        "Domain Name": registry_data.get("domainName", "N/A"),
                        "Registrar": registry_data.get("registrarName", "N/A"),
                        "Registration Date": registry_data.get("createdDate", "N/A"),
                        "Expiration Date": registry_data.get("expiresDate", "N/A"),
                        "Updated Date": registry_data.get("updatedDate", "N/A"),
                        "Name Servers": registry_data.get("nameServers", []),
                        "Status": registry_data.get("status", "N/A"),
                        "Registrant": registry_data.get("registrant", {}),
                        "Admin": registry_data.get("admin", {}),
                        "Technical": registry_data.get("technical", {}),
                        "Billing": registry_data.get("billing", {}),
                        "Zone": registry_data.get("zone", {}),
                        "Whois Server": registry_data.get("whoisServer", "N/A"),
                        "Referral URL": registry_data.get("referralURL", "N/A"),
                        "Registrar URL": registry_data.get("registrarURL", "N/A"),
                        "Creation Date": registry_data.get("createdDate", "N/A"),
                        "Emails": registry_data.get("emails", []),
                        "DNSSEC": registry_data.get("dnssec", "N/A"),
                        "Name": registry_data.get("name", "N/A"),
                        "Organization": registry_data.get("organization", "N/A"),
                        "Street": registry_data.get("street", "N/A"),
                        "City": registry_data.get("city", "N/A"),
                        "State": registry_data.get("state", "N/A"),
                        "Postal Code": registry_data.get("postalCode", "N/A"),
                        "Country": registry_data.get("country", "N/A"),
                    },
                    "error": None
                }

                results.append(result)
            else:
                error_message = data.get("ErrorMessage", "Unknown error")
                results.append({"domain": domain, "whois_data": None, "error": f"Error: {error_message}"})

        except Exception as e:
            results.append({"domain": domain, "whois_data": None, "error": f"Error: {str(e)}"})

    return results

# Replace 'YOUR_API_KEY' with your actual Whois API key
 whois_api_key = "at_3GpuyO8gF3sMMemWvX29cBH0aGQi1"

# Read domains from the external text file
 whois_requirements_file_path = "target-list.txt"
 whois_domains_to_check = extract_domains_from_requirements(whois_requirements_file_path)

 whois_results = check_domain_info(whois_api_key, whois_domains_to_check)
 for result in whois_results:
    print(f"\nDomain: {result['domain']}")
    print("=" * 100)  # Print nine equal signs for separation

    if result['error']:
        print(f"Error: {result['error']}")
    else:
        print("Whois Data:")
        for key, value in result['whois_data'].items():
            print(f"  {key}: {value}")

    print("=" * 100)  # Print nine equal signs for separation

# Exit the script after running whois analysis
 exit()


def readFunc(filename):
    output = []
    with open(filename, 'r') as f:
        for line in f:
            output.append(line.strip())
    return output

# ABUSE FUNC
def checkAbuse(value, counter):
    try:
        if ipPattern.search(value):

            abuse_url = 'https://api.abuseipdb.com/api/v2/check'

            querystring = {
                'ipAddress': value,
                'maxAgeInDays': '90'
            }
            abuse_headers = {
                'Accept': 'application/json',
                'Key': abuseApiKeys[counter % len(abuseApiKeys)]
            }

            abuse_response = requests.request(method='GET', url=abuse_url, headers=abuse_headers, params=querystring,
                                                    verify=False)
            decodedResponse = json.loads(abuse_response.text)

            ispName = decodedResponse['data']['isp']
            reportScore = decodedResponse['data']['abuseConfidenceScore']
            reportCount = decodedResponse['data']['totalReports']
            usageType = decodedResponse['data']['usageType']
        else:
            ispName, usageType = ("Can only check valid IP addresses on AbuseIPDB", "Can only check valid IP addresses on AbuseIPDB")
            reportCount, reportScore= (0, 0)
            returnJson = {
            "ispName" : "Can only check valid IP addresses on AbuseIPDB",
            "reportScore" : 0,
            "reportCount" : 0,
            "usageType" : "Can only check valid IP addresses on AbuseIPDB",
            "error" : True
                }
            return(returnJson)

        returnJson = {
            "ispName" : ispName,
            "reportScore" : reportScore,
            "reportCount" : reportCount,
            "usageType" : usageType,
            "error" : False
        }
        return(returnJson)
    except:
        returnJson = {
            "ispName" : "error",
            "reportScore" : 0,
            "reportCount" : 0,
            "usageType" : "error",
            "error" : True
        }
        return(returnJson)

# VIRUS TOTAL FUNC
def checkVirustotal(value, counter):
    try:
        if ipPattern.search(value):
            vtBaseUrl = "https://www.virustotal.com/api/v3/ip_addresses/"
        else:
            vtBaseUrl = "https://www.virustotal.com/api/v3/domains/"
        
        url = f"{vtBaseUrl}{value}"  # VT

        headers = {
            "accept": "application/json",
            "x-apikey": virustotalApiKeys[counter % len(virustotalApiKeys)]
        }

        response = requests.get(url, headers=headers, verify=False)
        json_file = json.loads(response.text)

        try:
            asOwner = json_file["data"]["attributes"]["as_owner"]
        except:
            asOwner = "None"
        lastAnalysisStats = json_file["data"]["attributes"]["last_analysis_stats"]
        isMalicious = json_file["data"]["attributes"]["last_analysis_stats"]["malicious"]

        returnJson = {
            "asOwner" : asOwner,
            "lastAnalysisStats" : lastAnalysisStats,
            "isMalicious" : isMalicious,
            "error" : False
        }
        
        return(returnJson)
    except:
        returnJson = {
            "asOwner" : "Error",
            "lastAnalysisStats" : {"Error": "Error with VirusTotal"},
            "isMalicious" : 0,
            "error" : True
        }
        return(returnJson)

def checking(value, counter):
    global htmlReport 
    global maliciousValues
    global totalCounter  
    global successfullyChecked
    global failedValues
    
    address = value
    ct = counter
    if not args.virustotal: 
        jsonVirustotal = checkVirustotal(address, ct)
        # VT VALUES
        asOwner = jsonVirustotal["asOwner"]
        lastAnalysisStats = jsonVirustotal["lastAnalysisStats"]
        isMalicious = jsonVirustotal["isMalicious"]
        vtError = jsonVirustotal["error"]
        print("\n==Virus Total=="+ ("=" * 35) + "\nAddress:" + address)
        print(f"\tAS Owner: {asOwner}")
        print("\tLast Analysis Stats:")
        for engine, result in lastAnalysisStats.items():
            if isinstance(result, dict):
                category = str(result['category'])
                method = str(result['method'])
                print(f"\t\t{engine}: {category} ({method})")
            else:
                print(f"\t\t{engine}: {result}")
    else:
        isMalicious = 0
        vtError = False
    if not args.abuse:
        jsonAbuse = checkAbuse(address, ct)
        # ABUSE VALUES
        ispName = jsonAbuse["ispName"]
        reportScore = jsonAbuse["reportScore"]
        reportCount = jsonAbuse["reportCount"]
        usageType = jsonAbuse["usageType"]
        abuseError = jsonAbuse["error"]
        print("==Abuse IP DB==" + ("=" *35) + "\nAddress:" + address + "\n\tISP Name: " + ispName + "\n\tAbuse Score: " + str(
                reportScore) + "\n\tReport Counts: " + str(reportCount) + "\n\tUsage Type: " + str(usageType))
    else:
        reportScore = 0
        reportCount = 0
        abuseError = False
        usageType = "NotChecked"

    #print("=" * 50)
    
    # APPEND isMalicious LIST
    if (int(isMalicious) >= args.virustotalreports or int(reportCount) >= args.abusereports or reportScore == 100) and usageType != "Reserved":
        maliciousValues.append(address)
    
    
    # CREATE HTML TABLE ROWS
    if args.report:
        startHtml = f'''
                <table border="1">
        '''
        endHtml = f'''
            </table>
        '''
            
        if not args.virustotal:
            
            vtHtml = f'''
                        <tr>
                            <th colspan="2">Address: {address}</th>
                        </tr>
                        <tr>
                            <td colspan="2" align="center"><strong><a href="https://www.virustotal.com/gui/search/{address}" target="_blank">Virus Total</a></strong></td>
                        </tr>
                        <tr>
                            <td>AS Owner:</td>
                            <td>{asOwner}</td>
                        </tr>
                        <tr>
                            <td>Last Analysis Stats:</td>
                            <td>
                                <table>
                                    {''.join(f'<tr><td>{engine}</td><td>{result["category"]}</td></tr>' if isinstance(result, dict) else f'<tr><td>{engine}</td><td>{result}</td></tr>' for engine, result in lastAnalysisStats.items())}
                                </table>
                            </td>
                        </tr>
                        '''
            startHtml = startHtml + vtHtml

        if not args.abuse:    
            abuseHtml = f'''            
                        <tr>
                            <td colspan="2" align="center"><strong><a href="https://www.abuseipdb.com/check/{address}" target="_blank">Abuse IP DB</a></strong></td>
                        </tr>
                        <tr>
                            <td><b>Address:</b></td>
                            <td><b>{address}</b></td>
                        </tr>
                        <tr> 
                            <td>ISP Name:</td>
                            <td>{ispName}</td>
                        </tr>
                        <tr>
                            <td>Abuse Score:</td>
                            <td>{reportScore}</td>
                        </tr>
                        <tr>
                            <td>Report Counts:</td>
                            <td>{reportCount}</td>
                        </tr>
                        <tr>
                            <td>Usage Type:</td>
                            <td>{usageType}</td>
                        </tr>
                    '''
            startHtml = startHtml + abuseHtml

        startHtml = startHtml + endHtml
        htmlReport.append(startHtml)
    
    if abuseError == True or vtError == True:
        failedValues.append(address)
    else:
        successfullyChecked = successfullyChecked + 1
    
    #totalCounter = totalCounter + 1


if __name__ == "__main__":
    
    # Control which APIs to use
    if args.virustotal and args.abuse:
        print("Not using any APIs, exitting...")
        exit() # Exit if user disabled both
    if args.virustotal is False:
        virustotalApiKeys = list(set(readFunc('api-keys/vt-apikeys.txt'))) # Get vt api keys
    if args.abuse is False:
        abuseApiKeys = list(set(readFunc('api-keys/abuse-apikeys.txt'))) # Get abuse api keys

    # INIT COUNTERS


    # GET VALUES
    if args.input is not None:
        print("Analyzing value: " + args.input)
        checkList = []
        checkList += [args.input]
    else:
        checkList = list(set(readFunc(args.path)))


    # START CHECKING THE VALUES
    # Number of threads specified by the user
    num_threads = args.threads
    
    threads = []
    for value in checkList:
        t = Thread(target=checking, args=(value, totalCounter))
        t.start()
        threads.append(t)
        totalCounter += 1

        # Limit the number of active threads based on the user's input
        if len(threads) >= num_threads:
            # Wait for the active threads to finish before creating new ones
            for thread in threads:
                thread.join()
            threads = []

    # Wait for any remaining threads to finish
    for thread in threads:
        thread.join()

    # END OF CHECKING 
    if args.report:
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
        with open(reportName, 'w') as html_file:
            html_css = '''
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }

        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }

        th {
            background-color: #f2f2f2;
        }

        td[colspan="2"] {
            text-align: center;
            font-weight: bold;
        }

        a {
            text-decoration: none;
        }
    </style>
    </head>
    <body>
    '''
            html_file.write( f"<h1>DomainCheckr Report</h1><h3>Issued on {formatted_time}</h3><h4>Successfully checked on {successfullyChecked} values out of {totalCounter}!</h4><h5> Arguments issued: {sys.argv}</h5>")
            html_file.write(html_css)
            for ip_html in htmlReport:
                html_file.write(ip_html)

            html_file.write(f"<table><br><tr><td><h4>Malicious Values</h4> (at least {str(args.virustotalreports)} reported on Virus Total or {str(args.abusereports)} on AbuseIPDB)</td></tr>")        
            for i in maliciousValues:
                html_file.write("<tr><td>%s</td></tr></body>" % i)
            html_file.write('</table></body>\n</html>')

            if failedValues:
                html_file.write('<table><br><tr><td><h4>Failed Values</h4></td></tr>')        
                for i in failedValues:
                    html_file.write("<tr><td>%s</td></tr></body>" % i)
                html_file.write('</table></body>\n</html>')
            html_file.write(f'Version {version}')

    print("=" * 50)
    print(f"\nMalicious Values are: (at least {str(args.virustotalreports)} reported on Virus Total or {str(args.abusereports)} on AbuseIPDB)\n")
    for i in maliciousValues:
        print("%s" % i)

    print(f"Successfully checked on {successfullyChecked} values out of {totalCounter}\n")

    print("Failed Values Are:\n")
    for i in failedValues:
        print("%s" % i)

    if args.report:
        print("\nOutput is also created as " + reportName + " in same directory")


