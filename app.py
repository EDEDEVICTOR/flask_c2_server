import os
from flask import Flask, request, jsonify, send_from_directory
from Crypto.Cipher import AES
import base64
from functools import wraps
import logging
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Access environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Setup basic logging
logging.basicConfig(level=logging.INFO)

# AES encryption setup
def encrypt_file(file_data):
    key = app.config['SECRET_KEY'].encode('utf-8')[:16]  # AES key should be 16, 24, or 32 bytes
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(encrypted_data):
    key = app.config['SECRET_KEY'].encode('utf-8')[:16]
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Decorator for role-based authentication
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = os.getenv('USER_ROLE', 'user')  # Default role is user
            if user_role != role:
                return jsonify({"error": "Unauthorized"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def home():
    return "Flask app with environment variables, encryption, and file uploads"

@app.route('/upload', methods=['POST'])
@role_required('admin')  # Only admin can upload
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Encrypt file before saving
        encrypted_file = encrypt_file(file.read())
        with open(filepath, 'wb') as f:
            f.write(encrypted_file)
        return jsonify({"message": "File uploaded successfully"}), 200
    return jsonify({"error": "File type not allowed"}), 400

@app.route('/download/<filename>', methods=['GET'])
@role_required('admin')  # Only admin can download
def download_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
            decrypted_data = decrypt_file(encrypted_data)
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)
