from flask import Flask, request, jsonify
import hashlib
import uuid
import os

app = Flask(__name__)

# Хранилище пользователей и ключей в памяти
users = {
    # Дефолтный админ: login -> {password, token, is_admin, subscription_days}
    "kot": {
        "password": hashlib.sha256("404sky".encode()).hexdigest(),
        "token": str(uuid.uuid4()),
        "is_admin": True,
        "subscription_days": 9999
    }
}
keys = {}  # key -> {days, used}

# Регистрация
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    if not login or not password:
        return jsonify({"error": "Login and password required"}), 400
    if login in users:
        return jsonify({"error": "Login already exists"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    token = str(uuid.uuid4())
    users[login] = {
        "password": hashed_password,
        "token": token,
        "is_admin": False,
        "subscription_days": 0
    }
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
    user = users.get(login)
    if user and user["password"] == hashed_password:
        return jsonify({
            "message": "Login successful",
            "token": user["token"],
            "is_admin": user["is_admin"],
            "subscription_days": user["subscription_days"]
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401

# Валидация токена
@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400

    for login, user in users.items():
        if user["token"] == token:
            return jsonify({
                "message": "Token valid",
                "login": login,
                "is_admin": user["is_admin"],
                "subscription_days": user["subscription_days"]
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

    # Проверка токена
    user_login = None
    for login, user in users.items():
        if user["token"] == token:
            user_login = login
            break
    if not user_login:
        return jsonify({"error": "Invalid token"}), 401

    # Проверка ключа
    if key not in keys:
        return jsonify({"error": "Invalid key"}), 400
    if keys[key]["used"]:
        return jsonify({"error": "Key already used"}), 400

    # Активация ключа
    users[user_login]["subscription_days"] += keys[key]["days"]
    keys[key]["used"] = True
    return jsonify({
        "message": "Key activated",
        "subscription_days": users[user_login]["subscription_days"]
    }), 200

# Админ-панель
@app.route('/admin', methods=['POST'])
def admin_panel():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token required"}), 400

    # Проверка админ-прав
    user_login = None
    for login, user in users.items():
        if user["token"] == token and user["is_admin"]:
            user_login = login
            break
    if not user_login:
        return jsonify({"error": "Admin access required"}), 403

    action = data.get('action')
    if action == "register":
        login = data.get('login')
        password = data.get('password')
        if not login or not password:
            return jsonify({"error": "Login and password required"}), 400
        if login in users:
            return jsonify({"error": "Login already exists"}), 400
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        token_new = str(uuid.uuid4())
        users[login] = {
            "password": hashed_password,
            "token": token_new,
            "is_admin": False,
            "subscription_days": 0
        }
        return jsonify({"message": f"User {login} registered by admin", "token": token_new}), 201

    elif action == "sub":
        login = data.get('login')
        days = data.get('days')
        if not login or not days:
            return jsonify({"error": "Login and days required"}), 400
        if login not in users:
            return jsonify({"error": "User not found"}), 404
        users[login]["subscription_days"] = days
        return jsonify({"message": f"User {login} subscribed for {days} days"}), 200

    elif action == "unsub":
        login = data.get('login')
        if not login:
            return jsonify({"error": "Login required"}), 400
        if login not in users:
            return jsonify({"error": "User not found"}), 404
        users[login]["subscription_days"] = 0
        return jsonify({"message": f"User {login} unsubscribed"}), 200

    elif action == "genkey":
        days = data.get('days')
        key = data.get('key')
        if not days or not key:
            return jsonify({"error": "Key and days required"}), 400
        if key in keys:
            return jsonify({"error": "Key already exists"}), 400
        keys[key] = {"days": days, "used": False}
        return jsonify({"message": "Key generated", "key": key, "days": days}), 200

    elif action == "list":
        user_list = [
            {"login": login, "subscription_days": user["subscription_days"], "is_admin": user["is_admin"]}
            for login, user in users.items()
        ]
        return jsonify({"message": "User list", "users": user_list}), 200

    return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
