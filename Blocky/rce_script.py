import argparse
import paramiko

def ssh_connect(host):
    username = "notch"
    password = "8YsqfCTnvxAUeduzjNSXe22"

    try:
        print(f"[+] Connecting to {host} as {username}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        print("[+] Connection successful!")

        while True:
            command = input(f"{username}@{host}$ ").strip()
            if command.lower() in ("exit", "quit"):
                print("[+] Disconnecting...")
                break
            if not command:
                continue

            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            print(output if output else error)

        client.close()

    except Exception as e:
        print("[-] Connection failed:", str(e))

def main():
    parser = argparse.ArgumentParser(description="Interactive SSH session with predefined credentials")
    parser.add_argument("host", help="Target host to SSH into (e.g., 192.168.1.10)")
    args = parser.parse_args()
    ssh_connect(args.host)

if __name__ == "__main__":
    main()
