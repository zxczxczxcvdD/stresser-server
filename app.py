from flask import Flask, request, jsonify
import sqlite3
import hashlib
import uuid
import os
import time

app = Flask(__name__)

# Инициализация базы данных
def init_db():
    if not os.path.exists("instance/users.db"):
        os.makedirs("instance", exist_ok=True)
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY, login TEXT UNIQUE, password TEXT, token TEXT, is_banned INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0, subscription_days INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (id TEXT PRIMARY KEY, key TEXT UNIQUE, days INTEGER, used_by TEXT, used_at TIMESTAMP)''')
    c.execute("SELECT login FROM users WHERE login = 'kot'")
    if not c.fetchone():
        hashed_password = hashlib.sha256("404sky".encode()).hexdigest()
        admin_token = str(uuid.uuid4())
        c.execute("INSERT INTO users (id, login, password, token, is_admin, subscription_days) VALUES (?, ?, ?, ?, ?, ?)",
                  (str(uuid.uuid4()), "kot", hashed_password, admin_token, 1, 30))
    conn.commit()
    conn.close()

init_db()

# Регистрация
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    if not login or not password:
        return jsonify({"error": "Login and password required"}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    token = str(uuid.uuid4())
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (id, login, password, token, subscription_days) VALUES (?, ?, ?, ?, ?)",
                  (str(uuid.uuid4()), login, hashed_password, token, 0))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Login exists"}), 400
    conn.close()
    
    return jsonify({"message": "Registered", "token": token, "subscription_days": 0}), 201

# Аутентификация
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    if not login or not password:
        return jsonify({"error": "Login and password required"}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute("SELECT token, is_banned, is_admin, subscription_days FROM users WHERE login = ? AND password = ?", (login, hashed_password))
    result = c.fetchone()
    conn.close()
    
    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "Banned"}), 403
        return jsonify({"message": "Logged in", "token": result[0], "is_admin": bool(result[2]), "subscription_days": result[3]}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Активация ключа
@app.route('/activate_key', methods=['POST'])
def activate_key():
    data = request.get_json()
    token = data.get('token')
    key = data.get('key')
    if not token or not key:
        return jsonify({"error": "Token and key required"}), 400
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute("SELECT login FROM users WHERE token = ?", (token,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Invalid token"}), 401
    login = user[0]
    
    c.execute("SELECT days, used_by FROM keys WHERE key = ? AND used_by IS NULL", (key,))
    key_data = c.fetchone()
    if not key_data:
        conn.close()
        return jsonify({"error": "Invalid or used key"}), 400
    days = key_data[0]
    
    c.execute("UPDATE users SET subscription_days = subscription_days + ? WHERE token = ?", (days, token))
    c.execute("UPDATE keys SET used_by = ?, used_at = ? WHERE key = ?", (login, time.time(), key))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Activated", "subscription_days": days}), 200

# Админ-панель
@app.route('/admin', methods=['POST'])
def admin_panel():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE token = ?", (token,))
    is_admin = c.fetchone()
    conn.close()
    
    if not is_admin or not is_admin[0]:
        return jsonify({"error": "Admin access required"}), 403
    
    action = data.get('action')
    if action == "reg":
        login = data.get('login')
        password = data.get('password')
        if not login or not password:
            return jsonify({"error": "Login and password required"}), 400
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        token_new = str(uuid.uuid4())
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (id, login, password, token, subscription_days) VALUES (?, ?, ?, ?, ?)",
                      (str(uuid.uuid4()), login, hashed_password, token_new, 0))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Login exists"}), 400
        conn.close()
        return jsonify({"message": "Registered", "token": token_new, "subscription_days": 0}), 201
    
    elif action == "ban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 1 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Banned", "login": login}), 200
    
    elif action == "unban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 0 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Unbanned", "login": login}), 200
    
    elif action == "sub":
        login = data.get('login')
        days = data.get('days')
        if not login or not days or not isinstance(days, int):
            return jsonify({"error": "Login and days required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = subscription_days + ? WHERE login = ?", (days, login))
        conn.commit()
        conn.close()
        return jsonify({"message": "Subscribed", "login": login, "days": days}), 200
    
    elif action == "unsub":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = 0 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Unsubscribed", "login": login}), 200
    
    elif action == "list":
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("SELECT login, is_banned, is_admin, subscription_days FROM users")
        users = [{"login": row[0], "is_banned": bool(row[1]), "is_admin": bool(row[2]), "subscription_days": row[3]} for row in c.fetchall()]
        conn.close()
        return jsonify({"message": "Users", "users": users}), 200
    
    elif action == "genkey":
        days = data.get('days')
        if not days or not isinstance(days, int):
            return jsonify({"error": "Days required"}), 400
        key = str(uuid.uuid4())
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("INSERT INTO keys (id, key, days) VALUES (?, ?, ?)", (str(uuid.uuid4()), key, days))
        conn.commit()
        conn.close()
        return jsonify({"message": "Generated", "key": key, "days": days}), 200
    
    return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
