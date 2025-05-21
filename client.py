import socket
import threading
import base64
from crypto_utils import *

HOST='192.168.0.106'
PORT=65432

pub_key = load_public_key()
aes_key= get_random_bytes(16)

def handle_receive(sock):
    while True:
        try:
            data=sock.recv(2048)
            if not data:
                break
            print(decrypt_aes(data.decode(), aes_key))
        except Exception as e:
            print(f"[Error recieving message]: {e}")
            break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        encrypted_key= encrypt_rsa(aes_key, pub_key)
        s.sendall(base64.b64encode(encrypted_key))

        data = s.recv(1024)
        if data:
            print(decrypt_aes(data.decode('utf-8'), aes_key), end=" ")

        username=input().strip()
        s.sendall(encrypt_aes(username, aes_key).encode())

        
        threading.Thread(target=handle_receive, args=(s,), daemon=True).start()
        
        while True:
            msg=input()
            s.sendall(encrypt_aes(msg, aes_key).encode())
            if msg.lower() =="/exit":
                print("[Exutubg]")
                break

if __name__=='__main__':
    main()