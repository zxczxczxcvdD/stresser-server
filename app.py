from flask import Flask, request, jsonify
import sqlite3
import hashlib
import uuid
import os

app = Flask(__name__)


# Инициализация базы данных
def init_db():
    if not os.path.exists("instance/users.db"):
        os.makedirs("instance", exist_ok=True)
    conn = sqlite3.connect("instance/users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY, login TEXT UNIQUE, password TEXT, token TEXT, is_banned INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0)''')

    # Дефолтный админ
    c.execute("SELECT login FROM users WHERE login = 'kot'")
    if not c.fetchone():
        hashed_password = hashlib.sha256("404sky".encode()).hexdigest()
        admin_token = str(uuid.uuid4())
        c.execute("INSERT INTO users (id, login, password, token, is_admin) VALUES (?, ?, ?, ?, ?)",
                  (str(uuid.uuid4()), "kot", hashed_password, admin_token, 1))
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
        c.execute("INSERT INTO users (id, login, password, token) VALUES (?, ?, ?, ?)",
                  (str(uuid.uuid4()), login, hashed_password, token))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Login already exists"}), 400
    conn.close()

    return jsonify({"message": "User registered", "token": token}), 201


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
    c.execute("SELECT token, is_banned, is_admin FROM users WHERE login = ? AND password = ?", (login, hashed_password))
    result = c.fetchone()
    conn.close()

    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "User is banned"}), 403
        return jsonify({"message": "Login successful", "token": result[0], "is_admin": bool(result[2])}), 200
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
    c.execute("SELECT login, is_banned, is_admin FROM users WHERE token = ?", (token,))
    result = c.fetchone()
    conn.close()

    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "User is banned"}), 403
        return jsonify({"message": "Token valid", "login": result[0], "is_admin": bool(result[2])}), 200
    return jsonify({"error": "Invalid token"}), 401


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
            c.execute("INSERT INTO users (id, login, password, token) VALUES (?, ?, ?, ?)",
                      (str(uuid.uuid4()), login, hashed_password, token_new))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Login already exists"}), 400
        conn.close()
        return jsonify({"message": "User registered by admin", "token": token_new}), 201

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

    elif action == "list":
        conn = sqlite3.connect("instance/users.db")
        c = conn.cursor()
        c.execute("SELECT login, is_banned, is_admin FROM users")
        users = [{"login": row[0], "is_banned": bool(row[1]), "is_admin": bool(row[2])} for row in c.fetchall()]
        conn.close()
        return jsonify({"message": "User list", "users": users}), 200

    return jsonify({"error": "Invalid action"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)