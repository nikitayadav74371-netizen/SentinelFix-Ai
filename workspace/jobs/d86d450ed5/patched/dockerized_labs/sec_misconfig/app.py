from flask import Flask, render_template, request, jsonify
import os
import traceback
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.debug = False

# Sensitive data for Lab 2 loaded from environment variables
SENSITIVE_DATA = {
    "database_url": os.environ.get("DATABASE_URL", ""),
    "api_key": os.environ.get("API_KEY", ""),
    "secret_key": os.environ.get("SECRET_KEY", ""),
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lab1")
def lab1():
    return render_template("lab1.html")


@app.route("/lab1/get-secret")
def get_secret():
    if request.headers.get("X-Host") == "admin.localhost:8000":
        secret = SENSITIVE_DATA["secret_key"]
        return jsonify({"secret": secret})
    else:
        return jsonify({"secret": None})


@app.route("/lab1/check-auth")
def check_auth():
    auth_header = request.headers.get("X-Custom-Auth")
    if auth_header == os.environ.get("AUTH_SECRET", ""):
        return jsonify({"success": True, "message": "Authentication successful!"})
    return jsonify({"success": False, "message": "Authentication failed."})


@app.route("/lab2")
def lab2():
    return render_template("lab2.html")


@app.errorhandler(404)
def page_not_found(e):
    # Sensitive configuration and credentials loaded from environment variables
    app_config = {
        "SECRET_KEY": os.environ.get("SECRET_KEY", ""),
        "DATABASE_URI": os.environ.get("DATABASE_URI", ""),
        "REDIS_PASSWORD": os.environ.get("REDIS_PASSWORD", ""),
        "AWS_ACCESS_KEY": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "AWS_SECRET_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "STRIPE_API_KEY": os.environ.get("STRIPE_API_KEY", ""),
        "ADMIN_CREDENTIALS": {
            "username": os.environ.get("ADMIN_USERNAME", "admin"),
            "password": os.environ.get("ADMIN_PASSWORD", ""),
        },
    }

    internal_apis = {
        "auth_service": os.environ.get("AUTH_SERVICE_URL", ""),
        "payment_service": os.environ.get("PAYMENT_SERVICE_URL", ""),
        "admin_panel": os.environ.get("ADMIN_PANEL_URL", ""),
    }

    return jsonify({"error": "Page not found"}), 404


@app.route("/lab3")
def lab3():
    return render_template("lab3.html")


@app.route("/lab3/get-token", methods=["POST"])
def get_token():
    data = request.get_json()
    username = data.get("username", "")
    role = data.get("role", "user")

    secret = os.environ.get("JWT_SECRET", "default_secret")

    token = jwt.encode(
        {
            "username": username,
            "role": role,
            "exp": datetime.utcnow() + timedelta(hours=1),
        },
        secret,
        algorithm="HS256",
    )
    return jsonify({"token": token})


@app.route("/lab3/verify-token", methods=["POST"])
def verify_token():
    token = request.get_json().get("token", "")
    secret = os.environ.get("JWT_SECRET", "default_secret")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        if payload["role"] == "admin":
            return jsonify(
                {"message": "Success! You gained admin access.", "payload": payload}
            )
        return jsonify(
            {"message": "Token verified but user is not admin", "payload": payload}
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route("/health")
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5009)
