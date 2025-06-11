import os
import sqlite3
import hashlib
import pickle
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials (A02:2021 - Cryptographic Failures)
USERNAME = "admin"
PASSWORD = "password123"

# Insecure hash (A03:2021 - Injection / A02)
def store_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# SQL Injection (A01:2021 - Broken Access Control / Injection)
@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    pwd = request.form['password']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
    cursor.execute(query)
    result = cursor.fetchone()
    return "Logged in!" if result else "Invalid credentials."

# Command Injection (A01)
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    return os.popen(f"ping -c 1 {host}").read()

# Insecure Deserialization (A08:2021)
@app.route('/unpickle', methods=['POST'])
def unpickle_data():
    data = request.data
    obj = pickle.loads(data)  # 🔥 Dangerous
    return f"Received: {obj}"

# XSS (A07:2021)
@app.route('/xss')
def xss():
    name = request.args.get('name', '')
    return f"<h1>Hello {name}</h1>"  # No escaping!

# Insecure File Access (A05:2021 - SSRF / Path Traversal)
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)
