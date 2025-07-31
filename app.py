import os
import pymysql
from flask import Flask, request, jsonify
import hashlib
import uuid
import time

app = Flask(__name__)

# Подключение к базе данных
def get_db_connection():
    db_url = os.environ.get('DATABASE_URL', 'mysql://root:zmUCAhJUXUKRoHNRweGnlZnqXQiBlPhv@turntable.proxy.rlwy.net:17278/railway')
    connection = pymysql.connect(
        host=db_url.split('@')[1].split(':')[0],
        port=int(db_url.split('@')[1].split(':')[1].split('/')[0]),
        user=db_url.split(':')[1].split('@')[0],
        password=db_url.split(':')[2].split('@')[0],
        database=db_url.split('/')[-1],
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection

# Инициализация базы данных
def init_db():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,
            login VARCHAR(255) UNIQUE,
            password VARCHAR(64),
            token VARCHAR(36),
            is_banned TINYINT DEFAULT 0,
            is_admin TINYINT DEFAULT 0,
            subscription_days INT DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
            id VARCHAR(36) PRIMARY KEY,
            key VARCHAR(36) UNIQUE,
            days INT,
            used_by VARCHAR(255),
            used_at TIMESTAMP)''')
        cursor.execute("SELECT login FROM users WHERE login = 'kot'")
        if not cursor.fetchone():
            hashed_password = hashlib.sha256("404sky".encode()).hexdigest()
            admin_token = str(uuid.uuid4())
            cursor.execute("INSERT INTO users (id, login, password, token, is_admin, subscription_days) VALUES (%s, %s, %s, %s, %s, %s)",
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
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        try:
            cursor.execute("INSERT INTO users (id, login, password, token, subscription_days) VALUES (%s, %s, %s, %s, %s)",
                           (str(uuid.uuid4()), login, hashed_password, token, 0))
            conn.commit()
        except pymysql.err.IntegrityError:
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
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT token, is_banned, is_admin, subscription_days FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        result = cursor.fetchone()
    conn.close()
    
    if result:
        if result['is_banned']:
            return jsonify({"error": "Banned"}), 403
        return jsonify({"message": "Logged in", "token": result['token'], "is_admin": bool(result['is_admin']), "subscription_days": result['subscription_days']}), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Активация ключа
@app.route('/activate_key', methods=['POST'])
def activate_key():
    data = request.get_json()
    token = data.get('token')
    key = data.get('key')
    if not token or not key:
        return jsonify({"error": "Token and key required"}), 400
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT login FROM users WHERE token = %s", (token,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "Invalid token"}), 401
        login = user['login']
        
        cursor.execute("SELECT days, used_by FROM keys WHERE key = %s AND used_by IS NULL", (key,))
        key_data = cursor.fetchone()
        if not key_data:
            conn.close()
            return jsonify({"error": "Invalid or used key"}), 400
        days = key_data['days']
        
        cursor.execute("UPDATE users SET subscription_days = subscription_days + %s WHERE token = %s", (days, token))
        cursor.execute("UPDATE keys SET used_by = %s, used_at = %s WHERE key = %s", (login, time.time(), key))
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
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT is_admin FROM users WHERE token = %s", (token,))
        is_admin = cursor.fetchone()
    conn.close()
    
    if not is_admin or not is_admin['is_admin']:
        return jsonify({"error": "Admin access required"}), 403
    
    action = data.get('action')
    if action == "reg":
        login = data.get('login')
        password = data.get('password')
        if not login or not password:
            return jsonify({"error": "Login and password required"}), 400
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        token_new = str(uuid.uuid4())
        conn = get_db_connection()
        with conn.cursor() as cursor:
            try:
                cursor.execute("INSERT INTO users (id, login, password, token, subscription_days) VALUES (%s, %s, %s, %s, %s)",
                               (str(uuid.uuid4()), login, hashed_password, token_new, 0))
                conn.commit()
            except pymysql.err.IntegrityError:
                conn.close()
                return jsonify({"error": "Login exists"}), 400
        conn.close()
        return jsonify({"message": "Registered", "login": login, "token": token_new, "subscription_days": 0}), 201
    
    elif action == "ban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET is_banned = 1 WHERE login = %s", (login,))
            conn.commit()
        conn.close()
        return jsonify({"message": "Banned", "login": login}), 200
    
    elif action == "unban":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET is_banned = 0 WHERE login = %s", (login,))
            conn.commit()
        conn.close()
        return jsonify({"message": "Unbanned", "login": login}), 200
    
    elif action == "sub":
        login = data.get('login')
        days = data.get('days')
        if not login or not days or not isinstance(days, int):
            return jsonify({"error": "Login and days required"}), 400
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET subscription_days = subscription_days + %s WHERE login = %s", (days, login))
            conn.commit()
        conn.close()
        return jsonify({"message": "Subscribed", "login": login, "days": days}), 200
    
    elif action == "unsub":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET subscription_days = 0 WHERE login = %s", (login,))
            conn.commit()
        conn.close()
        return jsonify({"message": "Unsubscribed", "login": login}), 200
    
    elif action == "list":
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT login, is_banned, is_admin, subscription_days FROM users")
            users = cursor.fetchall()
        conn.close()
        return jsonify({"message": "Users", "users": users}), 200
    
    elif action == "genkey":
        days = data.get('days')
        if not days or not isinstance(days, int):
            return jsonify({"error": "Days required"}), 400
        key = str(uuid.uuid4())
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO keys (id, key, days) VALUES (%s, %s, %s)", (str(uuid.uuid4()), key, days))
            conn.commit()
        conn.close()
        return jsonify({"message": "Generated", "key": key, "days": days}), 200
    
    return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
