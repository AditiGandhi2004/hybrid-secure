import socket
import threading
import argparse
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import hashes

def recv_messages(sock, private_key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            message = json.loads(data.decode())
            sender = message["from"]
            encrypted = bytes.fromhex(message["ciphertext"])
            # Decrypt incoming message
            plaintext = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"\n[{sender}] {plaintext.decode()}")
        except:
            break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--pub", required=True)
    parser.add_argument("--priv", required=True)
    args = parser.parse_args()

    # Load keys
    with open(args.priv, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    with open(args.pub, "rb") as f:
        peer_public_key = load_pem_public_key(f.read())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 65432))

    sock.send(json.dumps({
        "type": "register",
        "name": args.name
    }).encode())

    # Listen for incoming messages
    threading.Thread(target=recv_messages, args=(sock, private_key), daemon=True).start()

    print(f"Client {args.name} ready. Type messages to send to {args.peer}.")

    while True:
        msg = input("> ")
        encrypted = peer_public_key.encrypt(
            msg.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        sock.send(json.dumps({
            "type": "msg",
            "from": args.name,
            "to": args.peer,
            "ciphertext": encrypted.hex()
        }).encode())

if __name__ == "__main__":
    main()
