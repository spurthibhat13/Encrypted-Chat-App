
import socket, threading, base64, json
import tkinter as tk
from tkinter import scrolledtext, simpledialog, filedialog, messagebox
from crypto_utils import *

HOST = '192.162.0.0' #host ip address
PORT = 65432

pub_key = load_public_key()
aes_key = get_random_bytes(16)

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Encrypted Chat Client")

        self.chat_log = scrolledtext.ScrolledText(master, state='disabled', width=60, height=20)
        self.chat_log.grid(row=0, column=0, padx=10, pady=10)

        self.user_list = tk.Listbox(master, width=20, height=20)
        self.user_list.grid(row=0, column=2, padx=10, pady=10, sticky='ns')

        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.grid(row=1, column=0, padx=10, sticky='w')
        self.msg_entry.bind("<Return>", self.send_message)
        self.msg_entry.bind("<KeyRelease>", self.autocomplete_username)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=0, padx=10, sticky='e')

        self.file_button = tk.Button(master, text="Send File", command=self.send_file)
        self.file_button.grid(row=2, column=1, padx=10, sticky='e')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        encrypted_key = encrypt_rsa(aes_key, pub_key)
        self.sock.sendall(base64.b64encode(encrypted_key))

        greeting = decrypt_aes(self.sock.recv(1024).decode(), aes_key)
        username_input = simpledialog.askstring("Login", greeting)
        self.sock.sendall(encrypt_aes(username_input, aes_key).encode())

        password_prompt = decrypt_aes(self.sock.recv(1024).decode(), aes_key)
        password = simpledialog.askstring("Password", password_prompt, show='*')
        self.sock.sendall(encrypt_aes(password, aes_key).encode())

        login_response = decrypt_aes(self.sock.recv(1024).decode(), aes_key)
        if "failed" in login_response.lower():
            messagebox.showerror("Error", login_response)
            self.sock.close()
            master.destroy()
            return

        self.username = username_input
        master.title(f"Encrypted Chat - Logged in as {self.username}")
        self.running = True
        threading.Thread(target=self.recieve_messages, daemon=True).start()

        self.user_colors = {}
        self.color_palette = ["blue", "green", "purple", "orange", "magenta", "cyan", "red", "brown"]
        self.next_color_index = 0

    def recieve_messages(self):
        while self.running:
            try:
                data = self.sock.recv(2048)
                if not data:
                    break
                decrypted = decrypt_aes(data.decode(), aes_key)

                try:
                    msg_json = json.loads(decrypted)
                    if msg_json.get("type") == "user_list":
                        self.update_user_list(msg_json.get("users", []))
                        continue
                except json.JSONDecodeError:
                    pass

                try:
                    msg_json = json.loads(decrypted)
                    if msg_json.get("type") == "file":
                        filename = msg_json.get("filename")
                        file_b64 = msg_json.get("data")
                        sender = msg_json.get("from", "Unknown")

                        file_bytes = base64.b64decode(file_b64)
                        save_path = filedialog.asksaveasfilename(initialfile=filename)
                        if save_path:
                            with open(save_path, "wb") as f:
                                f.write(file_bytes)
                            self.display_message(f"[File from {sender} received and saved as {save_path}]")
                        else:
                            self.display_message(f"[File from {sender}] Not saved.")
                        continue
                except json.JSONDecodeError:
                    pass

                self.display_message(decrypted)
            except Exception as e:
                print(f"[Error receiving]: {e}")
                break

    def send_message(self, event=None):
        msg = self.msg_entry.get()
        if msg:
            try:
                self.sock.sendall(encrypt_aes(msg, aes_key).encode())
                self.msg_entry.delete(0, tk.END)
                self.display_message(f"[{self.username}]: {msg}")
            except Exception as e:
                self.display_message(f"[Error] Failed to send message: {e}")

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as f:
                file_bytes = f.read()
            file_b64 = base64.b64encode(file_bytes).decode()
            filename = file_path.split("/")[-1].split("\\")[-1]

            target = simpledialog.askstring("Send File", "Enter target username (or 'all'):")
            if target:
                file_msg = f"/file {target} {filename} {file_b64}"
                try:
                    self.sock.sendall(encrypt_aes(file_msg, aes_key).encode())
                    self.display_message(f"[You sent file '{filename}' to {target}]")
                except:
                    self.display_message("[Error] Failed to send file")

    def update_user_list(self, users):
        self.user_list.delete(0, tk.END)
        for user in users:
            self.user_list.insert(tk.END, user)

    def autocomplete_username(self, event=None):
        text = self.msg_entry.get()
        if text.startswith("/pm"):
            parts = text.split(' ')
            if len(parts) >= 2:
                prefix = parts[1].lower()
                matches = [u for u in self.user_list.get(0, tk.END) if u.lower().startswith(prefix)]
                if len(matches) == 1:
                    parts[1] = matches[0]
                    self.msg_entry.delete(0, tk.END)
                    self.msg_entry.insert(0, ' '.join(parts))

    def display_message(self, msg):
        self.chat_log.config(state='normal')
        if msg.startswith("[") and "]:" in msg:
            try:
                username = msg[1:msg.index("]:")]
                if username not in self.user_colors:
                    self.user_colors[username] = self.color_palette[self.next_color_index % len(self.color_palette)]
                    self.next_color_index += 1
                color = self.user_colors[username]
                self.chat_log.insert(tk.END, msg + "\n", username)
                self.chat_log.tag_config(username, foreground=color)
            except:
                self.chat_log.insert(tk.END, msg + "\n")
        else:
            self.chat_log.insert(tk.END, msg + "\n")
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)

    def close(self):
        self.running = False
        self.sock.close()
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.close)
    root.mainloop()
