import socket
import threading
import json

clients = {}

def handle_client(conn, addr):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            packet = json.loads(data.decode())

            # Register client name
            if packet["type"] == "register":
                name = packet["name"]
                clients[name] = conn
                print(f"Registered {name}")

            # Relay encrypted message
            elif packet["type"] == "msg":
                target = packet["to"]
                if target in clients:
                    clients[target].send(data)
                    print(f"Relayed message from {packet['from']} to {target}")
                else:
                    print(f"Target {target} not found")

        except Exception as e:
            print("Error:", e)
            break

    conn.close()

def main():
    host = "127.0.0.1"
    port = 65432
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()

    print(f"Server running on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    main()
