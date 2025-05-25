import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from encryption import encrypt_message, decrypt_message, key, cipher

HOST = '127.0.0.1'
PORT = 65432

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        self.root = tk.Tk()
        self.root.title("Secure Chat Client")

        self.chat_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.chat_area.pack(padx=10, pady=10)
        self.chat_area.config(state='disabled')

        self.entry = tk.Entry(self.root)
        self.entry.pack(padx=10, pady=10, fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        self.username = simpledialog.askstring("Username", "Enter your username:")
        self.sock.recv(1024)  # prompt
        self.sock.sendall(self.username.encode())

        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def receive_messages(self):
        while True:
            try:
                msg = self.sock.recv(1024)
                if not msg:
                    break
                decrypted = decrypt_message(msg)
                self.chat_area.config(state='normal')
                self.chat_area.insert(tk.END, decrypted + "\n")
                self.chat_area.yview(tk.END)
                self.chat_area.config(state='disabled')
            except:
                break

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg:
            encrypted = encrypt_message(msg)
            self.sock.sendall(encrypted)
            self.entry.delete(0, tk.END)

    def on_close(self):
        self.sock.close()
        self.root.destroy()

if __name__ == "__main__":
    ChatClient()
# This code is a simple chat client that connects to a server, sends and receives messages securely using encryption.