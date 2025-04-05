import os
import ssl
import time
import random
import base64
import hashlib
import requests
import uuid
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

# Setup logging
logging.basicConfig(filename='audit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Decrypt the configuration
def decrypt_config():
    with open("config.enc", "rb") as f:
        encrypted_data = f.read()

    aes_key = hashlib.sha256(b"EynDnmNF4fipxGmiErq0hMOC-lXBuBxgRhIAHQDM8XA").digest()  # AES Key
    iv = encrypted_data[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

    config = json.loads(decrypted_data.decode())
    return config

# Encrypt the configuration
def encrypt_config(config):
    aes_key = hashlib.sha256(b"EynDnmNF4fipxGmiErq0hMOC-lXBuBxgRhIAHQDM8XA").digest()  # AES Key
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(json.dumps(config).encode(), AES.block_size))

    with open("config.enc", "wb") as f:
        f.write(iv + encrypted_data)

# Load configuration from decrypted config file
config = decrypt_config()

# Flask App
app = Flask(__name__)

# User roles and permissions (extended)
roles_permissions = {
    "admin": ["view_logs", "run_commands", "upload_files", "download_files", "manage_users"],
    "operator": ["run_commands", "upload_files", "download_files"],
    "viewer": ["view_logs"]
}

# Role-based authentication system
def get_user_role(username):
    for user in config['users']:
        if user['username'] == username:
            return user['role']
    return None

def check_permission(role, permission):
    if permission in roles_permissions.get(role, []):
        return True
    return False

# Email alert system
def send_email_alert(subject, body):
    sender_email = "youremail@example.com"
    receiver_email = "alertrecipient@example.com"
    password = "youremailpassword"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)
            logging.info(f"Email sent: {subject}")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

# Registering client with logging
def register_client(client_id):
    # Simulate registration
    logging.info(f"Client {client_id} registered.")
    send_email_alert("New Client Registered", f"Client {client_id} has been successfully registered.")

# Commands handling with logging
@app.route('/command', methods=['POST'])
def execute_command():
    user = request.json.get('username')
    command = request.json.get('command')

    role = get_user_role(user)

    if not role:
        return jsonify({'status': 'error', 'message': 'Invalid username'}), 403

    if not check_permission(role, 'run_commands'):
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    # Simulate command execution
    result = f"Executed command: {command}"

    logging.info(f"Command executed by {user}: {command}")
    send_email_alert("Command Executed", f"User {user} executed command: {command}")

    return jsonify({'status': 'success', 'result': result})

# File upload (encrypted)
@app.route('/upload', methods=['POST'])
def upload_file():
    user = request.json.get('username')
    file_data = request.json.get('file_data')

    role = get_user_role(user)

    if not role:
        return jsonify({'status': 'error', 'message': 'Invalid username'}), 403

    if not check_permission(role, 'upload_files'):
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    # Simulate file upload
    encrypted_file_data = encrypt_command(file_data)
    logging.info(f"File uploaded by {user}")
    send_email_alert("File Uploaded", f"User {user} uploaded a file.")

    return jsonify({'status': 'success', 'message': 'File uploaded successfully.'})

# Encrypt file data before upload
def encrypt_command(cmd):
    iv = os.urandom(16)
    cipher = AES.new(hashlib.sha256(b"EynDnmNF4fipxGmiErq0hMOC-lXBuBxgRhIAHQDM8XA").digest(), AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(cmd.encode(), AES.block_size))

# Dashboard (Basic authentication for admin)
@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = request.args.get('username')
    role = get_user_role(username)

    if not role:
        return jsonify({'status': 'error', 'message': 'Invalid username'}), 403

    if role != 'admin':
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    # Display dashboard info
    return jsonify({'status': 'success', 'message': 'Welcome to the dashboard'})

# Start the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config['server']['port'], ssl_context='adhoc' if config['server']['use_https'] else None)
