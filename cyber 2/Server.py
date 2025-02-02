# server.py
import socket
import threading
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = '143.198.52.68'
SERVER_PORT = 8444
LOGS_DIR = "logs"

def send_json(sock, data):
    """Send a JSON message with a 4-byte length prefix."""
    msg = json.dumps(data).encode('utf-8')
    msg = len(msg).to_bytes(4, byteorder='big') + msg
    sock.sendall(msg)

def recv_json(sock):
    """Receive a JSON message that is prefixed with its 4-byte length."""
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    length = int.from_bytes(raw_length, byteorder='big')
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return json.loads(data.decode('utf-8'))

def load_private_key(path="private_key.pem"):
    """Load the server's RSA private key from a PEM file."""
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def handle_client(client_sock, addr, private_key):
    print(f"New connection from {addr}")
    aes_key = None
    client_mac = None

    # Expect the initialization message
    init_msg = recv_json(client_sock)
    if not init_msg or init_msg.get("type") != "init":
        print("Invalid or missing init message from", addr)
        client_sock.close()
        return

    client_mac = init_msg.get("mac")
    encrypted_aes_key_b64 = init_msg.get("encrypted_key")
    if not client_mac or not encrypted_aes_key_b64:
        print("Missing data in init message from", addr)
        client_sock.close()
        return

    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print("Failed to decrypt AES key from", addr, "Error:", e)
        client_sock.close()
        return

    print(f"Established session with {client_mac} from {addr}")

    # Ensure the logs directory exists
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    log_file_path = os.path.join(LOGS_DIR, f"{client_mac}.txt")

    # Process incoming log messages
    while True:
        try:
            msg = recv_json(client_sock)
            if msg is None:
                print("Connection closed by", addr)
                break
            if msg.get("type") == "log":
                encrypted_data_b64 = msg.get("data")
                if not encrypted_data_b64:
                    continue
                encrypted_data = base64.b64decode(encrypted_data_b64)
                # The first 12 bytes are the nonce for AESGCM
                nonce = encrypted_data[:12]
                ct = encrypted_data[12:]
                aesgcm = AESGCM(aes_key)
                try:
                    plaintext = aesgcm.decrypt(nonce, ct, None).decode('utf-8')
                except Exception as e:
                    print("Failed to decrypt log message from", addr, "Error:", e)
                    continue
                # Append the decrypted log text to the file
                with open(log_file_path, "a", encoding="utf-8") as f:
                    f.write(plaintext + "\n")
                print(f"Received log from {client_mac}: {plaintext}")
            else:
                print("Unknown message type from", addr)
        except Exception as e:
            print("Error handling client", addr, "Error:", e)
            break
    client_sock.close()

def main():
    private_key = load_private_key()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((SERVER_HOST, SERVER_PORT))
    server_sock.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_sock, addr = server_sock.accept()
        # Spawn a new thread for each client connection
        threading.Thread(target=handle_client, args=(client_sock, addr, private_key), daemon=True).start()

if __name__ == "__main__":
    main()
