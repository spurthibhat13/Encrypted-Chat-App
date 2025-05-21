import socket
import threading

HOST= '192.168.0.116'
PORT = 65432

def handle_recieve(conn):
    while True:
        try:
            data=conn.recv(1024)
            if not data:
                break
            print(f"\n[Client]: {data.decode()}")
        except:
            break

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}....")
        conn, addr=s.accept()
        print(f"[Server] Connected by {addr}")

        threading.Thread(target=handle_recieve, args=(conn,), daemon=True).start()

        while True:
            msg=input("You: ")
            conn.sendall(msg.encode())

if __name__=='__main__':
    main()