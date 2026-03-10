import os
import sqlite3
import subprocess
import hashlib
import random
import pickle
import requests
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# Intentionally vulnerable, hardcoded secret
app.config["SECRET_KEY"] = "super-secret-prod-key-123"

DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        """
    )
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 'test123')")
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Intentionally vulnerable, SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(query)
    row = cur.fetchone()
    conn.close()

    if row:
        return jsonify({"status": "ok", "message": "Logged in"})
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # Intentionally vulnerable, command injection
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{output}</pre>"


@app.route("/download")
def download():
    filename = request.args.get("file", "README.md")

    # Intentionally vulnerable, path traversal
    return send_file(filename)


@app.route("/hash", methods=["POST"])
def weak_hash():
    data = request.form.get("data", "")

    # Intentionally vulnerable, weak crypto
    digest = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"md5": digest})


@app.route("/deserialize", methods=["POST"])
def deserialize():
    payload = request.data

    # Intentionally vulnerable, insecure deserialization
    obj = pickle.loads(payload)
    return jsonify({"deserialized_type": str(type(obj))})


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")

    # Intentionally vulnerable, arbitrary code execution pattern via eval
    result = eval(expr)
    return jsonify({"result": str(result)})


@app.route("/token")
def token():
    # Intentionally vulnerable, predictable token generation
    token = "".join(str(random.randint(0, 9)) for _ in range(6))
    return jsonify({"token": token})


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")

    # Intentionally vulnerable, SSRF pattern
    resp = requests.get(url, timeout=2)
    return jsonify({"status_code": resp.status_code, "content": resp.text[:200]})


if __name__ == "__main__":
    init_db()

    # Intentionally vulnerable, debug mode enabled
    app.run(host="0.0.0.0", port=5000, debug=True)
