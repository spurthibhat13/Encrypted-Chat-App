from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64
import os

# AES with HMAC Encryption / Decryption

def encrypt_aes(msg, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding_len = 16 - len(msg.encode()) % 16
    padding = chr(padding_len) * padding_len
    padded_msg = msg + padding
    ciphertext = cipher.encrypt(padded_msg.encode())

    data = iv + ciphertext
    hmac = HMAC.new(key, data, SHA256).digest()
    full_msg = data + hmac
    encoded = base64.b64encode(full_msg).decode()
    return encoded

def decrypt_aes(encoded_msg, key):
    full_msg = base64.b64decode(encoded_msg)
    iv = full_msg[:16]
    hmac_received = full_msg[-32:]
    ciphertext = full_msg[16:-32]

    hmac_calc = HMAC.new(key, iv + ciphertext, SHA256)
    hmac_calc.verify(hmac_received)  # raises ValueError if invalid

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = cipher.decrypt(ciphertext)
    padding_len = padded_msg[-1]
    if isinstance(padding_len, str):
        padding_len = ord(padding_len)
    msg = padded_msg[:-padding_len].decode()
    return msg

# RSA Encryption / Decryption

def generate_rsa_keypair():
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open("private.pem", "wb") as prv_file:
            prv_file.write(private_key)
        with open("public.pem", "wb") as pub_file:
            pub_file.write(public_key)

def load_private_key():
    with open("private.pem", "rb") as f:
        key = RSA.import_key(f.read())
    return key

def load_public_key():
    with open("public.pem", "rb") as f:
        key = RSA.import_key(f.read())
    return key

def encrypt_rsa(msg_bytes, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(msg_bytes)
    return encrypted

def decrypt_rsa(encrypted_bytes, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(encrypted_bytes)
    return decrypted

def get_random_bytes(length):
    return os.urandom(length)
