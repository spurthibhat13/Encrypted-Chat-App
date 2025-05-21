import socket
import threading
from crypto_utils import *
import base64
import bcrypt
import json
import os

HOST = '0.0.0.0'
PORT = 65432

clients = {}  # {conn: (username, aes_key)}

CRED_FILE= 'credentials.json'

def load_credentials():
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_credentials(creds):
    with open(CRED_FILE, 'w') as f:
        json.dump(creds, f)

credentials= load_credentials()

generate_rsa_keypair()
priv_key = load_private_key()

def authenticate_user(conn, aes_key):
    conn.sendall(encrypt_aes("Enter your username:", aes_key).encode())
    username= decrypt_aes(conn.recv(1024).decode(), aes_key).strip()

    conn.sendall(encrypt_aes("Enter your password:", aes_key).encode())
    password= decrypt_aes(conn.recv(1024).decode(), aes_key).strip()

    if username in credentials:
        hashed_pw= credentials[username].encode()
        if bcrypt.checkpw(password.encode(), hashed_pw):
            conn.sendall(encrypt_aes("Login successful", aes_key).encode())
            return username
        else:
            conn.sendall(encrypt_aes("Authentication failed", aes_key).encode())
            return None
    else:
        hashed_pw= bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        credentials[username]=hashed_pw.decode()
        save_credentials(credentials)
        conn.sendall(encrypt_aes("User registered successfully", aes_key).encode())
        return username

def broadcast(message, sender_conn=None):
    to_remove=[]
    for conn, (_, key) in clients.items():
        if conn != sender_conn:
            try:
                encrypted_msg= encrypt_aes(message, key)
                conn.sendall(encrypted_msg.encode())
            except:
                conn.close()
                to_remove.append(conn)
    for conn in to_remove:
        clients.pop(conn, None)

def private_message(target_username, message, sender_username):
    for conn, (username, key) in clients.items():
        if username==target_username:
            enc_msg= encrypt_aes(f"[PM from {sender_username}]: {message}", key)
            conn.sendall(enc_msg.encode())
            return True
    return False

def broadcast_user_list():
    user_list= [username for _, (username,_) in clients.items()]
    msg=json.dumps({"type":"user_list", "users": user_list})
    for conn, (_, key) in clients.items():
        try:
            conn.sendall(encrypt_aes(msg, key).encode())
        except:
            continue

def handle_file_transfer(msg_dict, sender_conn, sender_username):
    filename= msg_dict['filename']
    file_data= msg_dict['data']
    for conn, (_, key) in clients.items():
        if conn!= sender_conn:
            file_msg= json.dumps({"type":"file", "filename":filename, "data":file_data, "from":sender_username})
            conn.sendall(encrypt_aes(file_msg, key).encode())

def handle_client(conn, addr):
    try:
        encrypted_key_b64= conn.recv(512)
        encrypted_key=base64.b64decode(encrypted_key_b64)
        aes_key=decrypt_rsa(encrypted_key, priv_key)

        username= authenticate_user(conn, aes_key)
        if not username:
            conn.close()
            return
        clients[conn]=(username, aes_key)
        print(f"[+] {username} connected from {addr}")
        broadcast(f"[{username} has joined the chat]")
        broadcast_user_list()

        while True:
            encrypted_data= conn.recv(2048)
            if not encrypted_data:
                break

            encrypted_str = encrypted_data.decode()
            print(f"[Encrypted from {username}]: {encrypted_str}")

            msg= decrypt_aes(encrypted_str, aes_key)
            print(f"[Decrypted from {username}]: {msg}")

            if msg.startswith("/pm "):
                try:
                    _, target, body=msg.split(" ", 2)
                    if not private_message(target, body, username):
                        conn.sendall(encrypt_aes("[Server]: User not found", aes_key).encode())
                except:
                    conn.sendall(encrypt_aes("[Server]: Usage: /pm <username> <message>", aes_key).encode())
            elif msg.startswith("/file "):
                try:
                    _, target_user, filename, file_b64 = msg.split(" ", 3)
                    send_file_to_user(target_user, filename, file_b64, username)
                except Exception as e:
                    print(f"[Server] File transfer error: {e}")
                    conn.sendall(encrypt_aes("[Server]: File transfer failed. Usage: /file <user|all> <filename> <base64_data>", aes_key).encode())

            else:
                broadcast(f"[{username}]: {msg}", sender_conn=conn)
    except Exception as e:
        print(f"[-] Error with {addr}: {e}")
    finally:
        if conn in clients:
            print(f"[-] {clients[conn][0]} disconnected")
            broadcast(f"[{clients[conn][0]} has left the chat]")
            del clients[conn]
        broadcast_user_list()
        conn.close()

def send_file_to_user(target, filename, file_b64, sender_username):
    file_msg_json = json.dumps({
        "type": "file",
        "from": sender_username,
        "filename": filename,
        "data": file_b64
    })

    for c, (uname, key) in clients.items():
        if target == "all" or uname == target:
            try:
                c.sendall(encrypt_aes(file_msg_json, key).encode())
            except Exception as e:
                print(f"[Server] Failed to send file to {uname}: {e}")


def main():
    server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[Server] Listening on {HOST}:{PORT}")
    
    while True:
        conn, addr= server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__=="__main__":
    main()