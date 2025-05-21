# Encrypted-Chat-App
Implementation of a secure chat system implemented in Python using AES encryption and key exchange through RSA with added message integrity.
The project includes a basic socket client-server chat through command line as well as a full-featured encrypted GUI chat with private messaging and encrypted file transfer.

--------------------------------------------------------------------------------------------------------------------------------

## Features

### GUI Encrypted Chat ('client_gui.py' + 'multiserver.py')
- Secure messaging using AES-256 encryption in CBC mode
- RSA public key encryption for AES key exchange
- Private messaging ('/pm <username> <message>')
- Encrypted file sharing
- User list display with autocomplete
- Tkinter-based GUI interface

### Basic Socket Chat ('client.py' + 'server.py')
- Simple client-server text messaging (no encryption)
- Gives a basic understanding for raw socket communication and client server model

--------------------------------------------------------------------------------------------------------------------------------

## Encryption Utilities- crypto_utils.py
This module handles all cryptographic operations and secure data transmission.

### AES Encryption/Decryption
- 'encrypt_aes(params)': Encrypts the message using AES-CBC and HMAC, returns base64-encoded string.
- 'decrypt_aes(params)': Verifies HMAC and decrypts the AES-CBC message.

### RSA Key Exchange
- 'load_public_key()': Loads or generates the RSA public key.
- 'load_private_key()': Loads or generates the RSA private key.
- 'encrypt_rsa(params)': Encrypts AES key using RSA public key.
- 'decrypt_rsa(params)': Decrypts AES key using RSA private key.

--------------------------------------------------------------------------------------------------------------------------------

## Project Workflow

### 1. Key Generation and Exchange
- When the client starts, it generates a random AES key.
- The client loads the server's RSA public key.
- The AES key is encrypted using RSA and sent to the server.
- Server decrypts AES key using its private key and uses it for all further communication.

### 2. Secure Login
- The server sends a greeting prompt, encrypted with AES.
- The client decrypts it and shows it via GUI input.
- The client then sends the username and password, encrypted with AES.
- The server verifies credentials and sends an encrypted login success or failure message.

### 3. Encrypted Messaging
- All text messages are encrypted using AES (CBC + HMAC).
- Clients can send public messages or use /pm <user> <message> to send encrypted private messages.
- The server routes the messages securely to intended recipients.

### 4. Encrypted File Transfer
- User selects a file via GUI.
- The file is base64-encoded, encrypted using AES, and sent to the server.
- The server routes it to the target user.
- The target user is prompted to save the file, which is decrypted and saved locally.

### 5. User Management
- Server maintains and updates a list of online users.
- The client periodically recieves the list and updates the GUI sidebar.
- Username autocomplete is supported for /pm and /file commands.

-----------------------------------------------------------------------------------------------------------------------------

## Future Improvements

1. **Group Chat Functionality** – Allow users to create and join group chats with end-to-end encryption.
2. **Persistent Chat Storage** – Implement secure database storage for message history and user sessions.
3. **Improved File Transfer** – Add support for large file uploads, transfer progress, and drag-and-drop interface.
4. **User Authentication System** – Introduce registration, login, and password management with optional 2FA.
5. **Cross-Platform Support** – Expand the client to work on mobile devices and web browsers using secure protocols.

-----------------------------------------------------------------------------------------------------------------------------

## License

This project is licensed under->MIT License, please check it out before using this resource.



