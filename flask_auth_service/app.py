import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
import sqlite3
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
from flask_mail import Mail, Message
from flask_cors import CORS

# NEW: RabbitMQ producer
from mq_producer import publish_event


# -------------------------
# App setup & configuration
# -------------------------
app = Flask(__name__)

# Allow requests from React frontend
CORS(app, origins=["*"])  # or ["*"] for any origin

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["DATABASE"] = os.environ.get("DATABASE", os.path.join(app.root_path, "app.db"))
app.config["SECURITY_PASSWORD_SALT"] = os.environ.get("SECURITY_PASSWORD_SALT", "dev-salt-change-me")

# Mailtrap SMTP configuration
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USERNAME"] = "4d79f1f2784687"
app.config["MAIL_PASSWORD"] = "e97548708293bc"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

mail = Mail(app)

# Serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# -------------------------
# Database helpers
# -------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id uniqueidentifier PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()


@app.before_request
def before_request():
    init_db()


# -------------------------
# Small helpers
# -------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[+]?[0-9]\d{1,14}$")  # E.164 format


def validate_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))

def validate_phone(phone: str) -> bool:
    return bool(PHONE_RE.match(phone or ""))


def logged_in() -> bool:
    return bool(session.get("user_id"))


def get_current_user():
    if not logged_in():
        return None
    db = get_db()
    return db.execute(
        "SELECT id, email, created_at FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()


# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip().lower() or "0123456789"
        phone = request.form.get("phone", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        errors = []
        if not validate_email(email):
            errors.append("Please enter a valid email address.")
        if not validate_phone(phone):
            errors.append("Please enter a valid phone number.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if len(name) == 0:
            errors.append("Name is required.")
        if password != password2:
            errors.append("Passwords do not match.")

        if not errors:
            db = get_db()
            exists = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()

            if exists:
                errors.append("An account with that email already exists.")
            else:
                password_hash = generate_password_hash(password)
                cursor = db.execute(
                    "INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        name,
                        email,
                        phone,
                        password_hash,
                        datetime.utcnow().isoformat(timespec="seconds"),
                    ),
                )
                db.commit()

                user_id = cursor.lastrowid

                try:
                    # NEW: Publish MQ user_registered event
                    message = {
                        "type": "user_registered",
                        "data": {
                            "id": user_id,
                            "email": email,
                        },
                    }
                    publish_event("rk-register-user", message)
                    print(f"Push message success for user id {user_id}")
                except Exception as e:
                    print(f"Push message error for user id {user_id}: {e}")
                
                flash("Registration successful. You can now log in.", "success")
                return redirect(url_for("login"))

        for e in errors:
            flash(e, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not validate_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("forgot.html")

        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

        token = serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])
        reset_url = url_for("reset_password", token=token, _external=True)

        msg = Message(
            "Stayli Password Reset",
            sender="no-reply@stayli.com",
            recipients=[email],
        )
        msg.body = (
            f"Hello,\n\nClick this link to reset your Stayli password:\n"
            f"{reset_url}\n\nIf you didn't request this, ignore this email."
        )

        mail.send(msg)

        flash("If this email exists, we have sent a reset link.", "info")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt=app.config["SECURITY_PASSWORD_SALT"],
            max_age=3600,
        )
    except SignatureExpired:
        flash("Reset link expired.", "error")
        return redirect(url_for("forgot"))
    except BadSignature:
        flash("Invalid reset link.", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if password != password2:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            db = get_db()
            password_hash = generate_password_hash(password)
            db.execute(
                "UPDATE users SET password_hash = ? WHERE email = ?",
                (password_hash, email),
            )
            db.commit()
            flash("Password has been reset. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("reset.html", email=email)


# -------------------------
# API Endpoints
# -------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip().lower()
    password = data.get("password") or ""
    password2 = data.get("password2") or ""

    errors = []
    if not validate_email(email):
        errors.append("Please enter a valid email address.")
    if not validate_phone(phone):
        errors.append("Please enter a valid phone number.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if len(name) == 0:
        errors.append("Name is required.")
    if password != password2:
        errors.append("Passwords do not match.")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
    if exists:
        return jsonify({"success": False, "errors": ["Email already exists."]}), 400
    
    exists = db.execute("SELECT 1 FROM users WHERE phone = ?", (phone,)).fetchone()
    if exists:
        return jsonify({"success": False, "errors": ["Phone already exists."]}), 400

    password_hash = generate_password_hash(password)
    user_id = str(uuid.uuid4())
    cursor = db.execute(
        "INSERT INTO users (id, name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, email, phone, password_hash, datetime.utcnow().isoformat(timespec="seconds")),
    )
    db.commit()

    try:
        # NEW: Publish MQ user_registered event
        message = {
            "id": user_id,
            "email": email,
            "name" : name,
            "phone" : phone,
        }
        publish_event("rk-register-user", message)
    except Exception as e:
        print(f"Push message error: {e}")

    return jsonify({"success": True, "message": "User created successfully"}), 201

@app.route("/api/update-profile", methods=["POST"])
def api_update():
    data = request.get_json() or {}
    id = (data.get("id") or "").strip().lower()
    name = (data.get("name") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip().lower()

    errors = []
    if not validate_email(email):
        errors.append("Please enter a valid email address.")
    if not validate_phone(phone):
        errors.append("Please enter a valid phone number.")
    if len(name) == 0:
        errors.append("Name is required.")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE id = ?", (id,)).fetchone()
    if not exists:
        return jsonify({"success": False, "errors": ["Use not found."]}), 400
    
    exists = db.execute("SELECT 1 FROM users WHERE email = ? and id != ?", (email, id)).fetchone()
    if exists:
        return jsonify({"success": False, "errors": ["Email already exists."]}), 400
    
    exists = db.execute("SELECT 1 FROM users WHERE phone = ? and id != ?", (phone, id)).fetchone()
    if exists:
        return jsonify({"success": False, "errors": ["Phone already exists."]}), 400
    
    db.execute(
        "UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?",
        (name, email, phone, id),
    )
    db.commit()

    try:
        # NEW: Publish MQ user_updated event
        message = {
            "id": id,
            "email": email,
            "name" : name,
            "phone" : phone,
        }
        publish_event("rk-update-user", message)
    except Exception as e:
        print(f"Push message error: {e}")

    return jsonify({"success": True, "message": "User updated successfully"}), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute(
        "SELECT id, name, email, phone, password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"],
        }
    }), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    }), 200


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not validate_email(email):
        return jsonify({
            "success": True,
            "message": "If this email exists, a reset link was sent."
        }), 200

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        return jsonify({
            "success": True,
            "message": "If this email exists, a reset link was sent."
        }), 200

    token = serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])
    reset_url = url_for("reset_password", token=token, _external=True)

    msg = Message(
        "Stayli Password Reset",
        sender="no-reply@stayli.com",
        recipients=[email],
    )
    msg.body = (
        f"Hello,\n\nClick this link to reset your Stayli password:\n"
        f"{reset_url}\n\nIf you didn't request this, ignore this email."
    )
    mail.send(msg)

    return jsonify({
        "success": True,
        "message": "If this email exists, a reset link was sent."
    }), 200


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json() or {}
    email = data.get("email") or ""
    currentPassword = data.get("currentPassword") or ""
    newPassword = data.get("newPassword") or ""
    newPassword2 = data.get("newPassword2") or ""

    # try:
    #     email = serializer.loads(
    #         token,
    #         salt=app.config["SECURITY_PASSWORD_SALT"],
    #         max_age=3600,
    #     )
    # except SignatureExpired:
    #     return jsonify({"success": False, "error": "Reset link expired."}), 400
    # except BadSignature:
    #     return jsonify({"success": False, "error": "Invalid reset link."}), 400
    
    

    errors = []
    if len(newPassword) < 8:
        errors.append("Password must be at least 8 characters long.")
    if newPassword != newPassword2:
        errors.append("Passwords do not match.")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400
    
    db = get_db()
    result = db.execute(
        "SELECT password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()
    
    if not result or not check_password_hash(result["password_hash"], currentPassword):
        return jsonify({"success": False, "error": "Current password is incorrect."}), 401

    password_hash = generate_password_hash(newPassword)
    db.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (password_hash, email),
    )
    db.commit()

    return jsonify({"success": True, "message": "Password has been reset."}), 200


# -------------------------
# Run the app
# -------------------------
if __name__ == "__main__":
    app.run(
        # ssl_context='adhoc',
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True,
    )
