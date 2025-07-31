from flask import Flask, request, jsonify
import uuid
import time

app = Flask(__name__)

users = {
    "kot": {"password": "404sky", "token": str(uuid.uuid4()), "is_admin": True, "subscription_days": 9999, "balance": 0.0, "referral_code": "admin_kot"},
    "404sky": {"password": "404sky", "token": str(uuid.uuid4()), "is_admin": True, "subscription_days": 9999, "balance": 0.0, "referral_code": "admin_404sky"}
}
keys = {}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    login, password = data.get("login"), data.get("password")
    if login in users and users[login]["password"] == password:
        return jsonify({"token": users[login]["token"], "is_admin": users[login]["is_admin"], "subscription_days": users[login]["subscription_days"], "balance": users[login]["balance"]})
    return jsonify({"error": "Invalid login or password"}), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    login, password = data.get("login"), data.get("password")
    if login in users:
        return jsonify({"error": "Login already exists"}), 400
    token = str(uuid.uuid4())
    referral_code = str(uuid.uuid4())[:8]
    users[login] = {"password": password, "token": token, "is_admin": False, "subscription_days": 0, "balance": 0.0, "referral_code": referral_code}
    return jsonify({"token": token, "subscription_days": 0, "balance": 0.0})

@app.route("/activate_key", methods=["POST"])
def activate_key():
    data = request.get_json()
    token, key = data.get("token"), data.get("key")
    for login, user in users.items():
        if user["token"] == token:
            if key in keys and not keys[key]["used"]:
                keys[key]["used"] = True
                users[login]["subscription_days"] += keys[key]["days"]
                if keys[key].get("used_in_bot") and keys[key].get("used_in_loader"):
                    return jsonify({"error": "Key already used in both bot and loader"}), 400
                keys[key]["used_in_loader"] = True
                if keys[key].get("referrer"):
                    users[keys[key]["referrer"]]["balance"] += keys[key]["days"] * 0.1  # 10% бонус за реферала
                return jsonify({"subscription_days": users[login]["subscription_days"]})
            return jsonify({"error": "Invalid or used key"}), 400
    return jsonify({"error": "Invalid token"}), 401

@app.route("/activate_key_bot", methods=["POST"])
def activate_key_bot():
    data = request.get_json()
    token, key = data.get("token"), data.get("key")
    for login, user in users.items():
        if user["token"] == token:
            if key in keys and not keys[key]["used"]:
                keys[key]["used"] = True
                users[login]["subscription_days"] += keys[key]["days"]
                if keys[key].get("used_in_bot") and keys[key].get("used_in_loader"):
                    return jsonify({"error": "Key already used in both bot and loader"}), 400
                keys[key]["used_in_bot"] = True
                if keys[key].get("referrer"):
                    users[keys[key]["referrer"]]["balance"] += keys[key]["days"] * 0.1
                return jsonify({"subscription_days": users[login]["subscription_days"]})
            return jsonify({"error": "Invalid or used key"}), 400
    return jsonify({"error": "Invalid token"}), 401

@app.route("/add_balance", methods=["POST"])
def add_balance():
    data = request.get_json()
    token, amount = data.get("token"), data.get("amount")
    for login, user in users.items():
        if user["token"] == token and user["is_admin"]:
            target_login = data.get("login")
            if target_login in users:
                users[target_login]["balance"] += amount
                return jsonify({"message": f"Added {amount} to {target_login}'s balance", "new_balance": users[target_login]["balance"]})
            return jsonify({"error": "User not found"}), 404
    return jsonify({"error": "Admin access required"}), 401

@app.route("/withdraw_balance", methods=["POST"])
def withdraw_balance():
    data = request.get_json()
    token, amount = data.get("token"), data.get("amount")
    for login, user in users.items():
        if user["token"] == token:
            if user["balance"] >= amount:
                user["balance"] -= amount
                return jsonify({"message": f"Withdrawn {amount} from {login}'s balance", "new_balance": user["balance"]})
            return jsonify({"error": "Insufficient balance"}), 400
    return jsonify({"error": "Invalid token"}), 401

@app.route("/admin", methods=["POST"])
def admin():
    data = request.get_json()
    token, action = data.get("token"), data.get("action")
    for login, user in users.items():
        if user["token"] == token and user["is_admin"]:
            if action == "reg":
                new_login, new_password = data.get("login"), data.get("password")
                if new_login in users:
                    return jsonify({"error": "Login already exists"}), 400
                new_token = str(uuid.uuid4())
                new_referral_code = str(uuid.uuid4())[:8]
                users[new_login] = {"password": new_password, "token": new_token, "is_admin": False, "subscription_days": 0, "balance": 0.0, "referral_code": new_referral_code}
                return jsonify({"message": f"Registered {new_login}"})
            elif action == "sub":
                target_login, days = data.get("login"), data.get("days")
                if target_login in users:
                    users[target_login]["subscription_days"] += days
                    return jsonify({"message": f"Subscribed {target_login} for {days} days"})
                return jsonify({"error": "User not found"}), 404
            elif action == "unsub":
                target_login = data.get("login")
                if target_login in users:
                    users[target_login]["subscription_days"] = 0
                    return jsonify({"message": f"Unsubscribed {target_login}"})
                return jsonify({"error": "User not found"}), 404
            elif action == "genkey":
                days = data.get("days")
                key = str(uuid.uuid4())
                keys[key] = {"days": days, "used": False, "used_in_bot": False, "used_in_loader": False, "referrer": login}
                return jsonify({"key": key, "days": days})
            elif action == "list":
                return jsonify({"users": [{"login": k, "subscription_days": v["subscription_days"], "balance": v["balance"]} for k, v in users.items()]})
    return jsonify({"error": "Admin access required"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
