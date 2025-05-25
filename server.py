import socket
import threading
from encryption import encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 65432

clients = {}
lock = threading.Lock()

def broadcast(message, sender_conn=None):
    with lock:
        for conn in clients:
            if conn != sender_conn:
                try:
                    conn.sendall(encrypt_message(message))
                except:
                    conn.close()
                    del clients[conn]

def handle_client(conn, addr):
    try:
        conn.sendall(b"Enter your username: ")
        username = conn.recv(1024).decode().strip()
        with lock:
            clients[conn] = username
        broadcast(f"{username} has joined the chat!", conn)

        while True:
            msg = conn.recv(1024)
            if not msg:
                break
            decrypted_msg = decrypt_message(msg)
            full_msg = f"{username}: {decrypted_msg}"
            broadcast(full_msg, conn)
    except:
        pass
    finally:
        with lock:
            if conn in clients:
                broadcast(f"{clients[conn]} has left the chat.")
                del clients[conn]
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

start_server()
# This code is a simple chat server that uses encryption to secure messages.