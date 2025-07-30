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
        return jsonify({"error": "Login already exists"}), 400
    conn.close()
    
    return jsonify({"message": "User registered", "token": token, "subscription_days": 0}), 201

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
            return jsonify({"error": "User is banned"}), 403
        return jsonify({"message": "Login successful", "token": result[0], "is_admin": bool(result[2]), "subscription_days": result[3]}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Валидация токена
@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute("SELECT login, is_banned, is_admin, subscription_days FROM users WHERE token = ?", (token,))
    result = c.fetchone()
    conn.close()
    
    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "User is banned"}), 403
        return jsonify({"message": "Token valid", "login": result[0], "is_admin": bool(result[2]), "subscription_days": result[3]}), 200
    return jsonify({"error": "Invalid token"}), 401

# Чат
@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    token = data.get('token')
    message = data.get('message')
    if not token or not message:
        return jsonify({"error": "Token and message required"}), 400
    
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute("SELECT login FROM users WHERE token = ?", (token,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "Invalid token"}), 401
    
    login = user[0]
    # Здесь можно добавить сохранение сообщений в отдельную таблицу для истории
    return jsonify({"message": f"{login}: {message}", "timestamp": time.time()}), 200

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
    if action == "register":
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
            return jsonify({"error": "Login already exists"}), 400
        conn.close()
        return jsonify({"message": "User registered by admin", "token": token_new, "subscription_days": 0}), 201
    
    elif action == "ban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 1 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} banned"}), 200
    
    elif action == "unban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 0 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} unbanned"}), 200
    
    elif action == "subscribe":
        login = data.get('login')
        days = data.get('days')
        if not login or not days or not isinstance(days, int):
            return jsonify({"error": "Login and valid days required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = subscription_days + ? WHERE login = ?", (days, login))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Added {days} days to {login}'s subscription"}), 200
    
    elif action == "unsubscribe":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = 0 WHERE login = ?", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Removed subscription from {login}"}), 200
    
    elif action == "list":
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("SELECT login, is_banned, is_admin, subscription_days FROM users")
        users = [{"login": row[0], "is_banned": bool(row[1]), "is_admin": bool(row[2]), "subscription_days": row[3]} for row in c.fetchall()]
        conn.close()
        return jsonify({"message": "User list", "users": users}), 200
    
    return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
