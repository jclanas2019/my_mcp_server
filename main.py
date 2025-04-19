#!/usr/bin/env python3
import socket
import json
import threading
from handler import handle_message
from registry import init_registry

HOST = "0.0.0.0"
PORT = 5050
BUFFER_SIZE = 4096

def handle_client(conn, addr):
    print(f"📡 Conexión activa desde {addr}")
    with conn:
        buffer = b""
        while True:
            try:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buffer += chunk
                try:
                    message = json.loads(buffer.decode("utf-8"))
                    response = handle_message(message)
                    conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                    buffer = b""
                except json.JSONDecodeError:
                    continue  # espera más data
            except Exception as e:
                print(f"❌ Error con {addr}: {e}")
                break
    print(f"🔌 Conexión cerrada: {addr}")

if __name__ == "__main__":
    init_registry()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"✅ Servidor MCP TCP multicliente escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()
