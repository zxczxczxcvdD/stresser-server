from flask import Flask, request, jsonify
import psycopg2
import hashlib
import uuid
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Загрузка переменных окружения
load_dotenv()

# Подключение к PostgreSQL
def get_db_connection():
    conn = psycopg2.connect(os.getenv("postgresql://postgres:uPecyIETSXrGszgYNIvvmOEHOjTqiijL@turntable.proxy.rlwy.net:23379/railway"))
    return conn

# Инициализация базы данных
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            login TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token TEXT NOT NULL,
            is_banned INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            subscription_days INTEGER DEFAULT 0
        )
    ''')

    # Дефолтный админ
    c.execute("SELECT login FROM users WHERE login = 'kot'")
    if not c.fetchone():
        hashed_password = hashlib.sha256("404sky".encode()).hexdigest()
        admin_token = str(uuid.uuid4())
        c.execute(
            "INSERT INTO users (id, login, password, token, is_admin) VALUES (%s, %s, %s, %s, %s)",
            (str(uuid.uuid4()), "kot", hashed_password, admin_token, 1)
        )
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

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (id, login, password, token, subscription_days) VALUES (%s, %s, %s, %s, %s)",
            (str(uuid.uuid4()), login, hashed_password, token, 0)
        )
        conn.commit()
    except psycopg2.IntegrityError:
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

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT token, is_banned, is_admin, subscription_days FROM users WHERE login = %s AND password = %s",
        (login, hashed_password)
    )
    result = c.fetchone()
    conn.close()

    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "User is banned"}), 403
        return jsonify({
            "message": "Login successful",
            "token": result[0],
            "is_admin": bool(result[2]),
            "subscription_days": result[3]
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Валидация токена
@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT login, is_banned, is_admin, subscription_days FROM users WHERE token = %s",
        (token,)
    )
    result = c.fetchone()
    conn.close()

    if result:
        if result[1]:  # is_banned
            return jsonify({"error": "User is banned"}), 403
        return jsonify({
            "message": "Token valid",
            "login": result[0],
            "is_admin": bool(result[2]),
            "subscription_days": result[3]
        }), 200
    return jsonify({"error": "Invalid token"}), 401

# Активация ключа
@app.route('/activate_key', methods=['POST'])
def activate_key():
    data = request.get_json()
    token = data.get('token')
    key = data.get('key')
    if not token or not key:
        return jsonify({"error": "Token and key required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT login FROM users WHERE token = %s", (token,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Invalid token"}), 401

    # Пример: для простоты ключ даёт 30 дней подписки
    c.execute("UPDATE users SET subscription_days = %s WHERE token = %s", (30, token))
    conn.commit()
    c.execute("SELECT subscription_days FROM users WHERE token = %s", (token,))
    subscription_days = c.fetchone()[0]
    conn.close()

    return jsonify({"message": "Key activated", "subscription_days": subscription_days}), 200

# Админ-панель
@app.route('/admin', methods=['POST'])
def admin_panel():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE token = %s", (token,))
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
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (id, login, password, token, subscription_days) VALUES (%s, %s, %s, %s, %s)",
                (str(uuid.uuid4()), login, hashed_password, token_new, 0)
            )
            conn.commit()
        except psycopg2.IntegrityError:
            conn.close()
            return jsonify({"error": "Login already exists"}), 400
        conn.close()
        return jsonify({"message": "User registered by admin", "token": token_new}), 201

    elif action == "ban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 1 WHERE login = %s", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} banned"}), 200

    elif action == "unban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned = 0 WHERE login = %s", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} unbanned"}), 200

    elif action == "sub":
        login = data.get('login')
        days = data.get('days')
        if not login or not days:
            return jsonify({"error": "Login and days required"}), 400
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = %s WHERE login = %s", (days, login))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} subscribed for {days} days"}), 200

    elif action == "unsub":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET subscription_days = 0 WHERE login = %s", (login,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {login} unsubscribed"}), 200

    elif action == "list":
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT login, is_banned, is_admin, subscription_days FROM users")
        users = [
            {"login": row[0], "is_banned": bool(row[1]), "is_admin": bool(row[2]), "subscription_days": row[3]}
            for row in c.fetchall()
        ]
        conn.close()
        return jsonify({"message": "User list", "users": users}), 200

    elif action == "genkey":
        days = data.get('days')
        key = data.get('key')
        if not days or not key:
            return jsonify({"error": "Key and days required"}), 400
        # Для простоты ключ пока не сохраняется в базе, только возвращается
        return jsonify({"message": "Key generated", "key": key, "days": days}), 200

    return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
