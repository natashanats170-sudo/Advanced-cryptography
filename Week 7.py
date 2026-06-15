/Code Example 1 — SQL Injection (Vulnerable vs Safe)/

python
# ❌ VULNERABLE — user input directly in query string
import sqlite3

def login_vulnerable(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

# Attacker input: username = "admin'--"  password = "anything"
# Resulting query: SELECT * FROM users WHERE username='admin'--' AND password='anything'
# The -- comments out the password check — authentication bypassed!


# ✅ SAFE — parameterized query (prepared statement)
def login_safe(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))  # values passed separately
    return cursor.fetchone()
# No matter what the user types, it is treated as data, never as SQL code.


/Code Example 2 — Broken Access Control (Vulnerable vs Safe)./

python
# ❌ VULNERABLE — no check that the logged-in user owns the record
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/account")
def get_account_vulnerable():
    user_id = request.args.get("id")   # attacker can pass ANY id
    record  = db.query(f"SELECT * FROM accounts WHERE id={user_id}")
    return jsonify(record)


# ✅ SAFE — enforce ownership check
@app.route("/account")
def get_account_safe():
    current_user = get_logged_in_user()      # from session/token
    user_id      = request.args.get("id")
    if str(current_user.id) != str(user_id): # ownership check
        return jsonify({"error": "Forbidden"}), 403
    record = db.query("SELECT * FROM accounts WHERE id=?", user_id)
    return jsonify(record)


/Code Example 3 — Input Validation and XSS Prevention./

python
# ❌ VULNERABLE — raw user input reflected back in HTML (XSS)
from flask import request

@app.route("/search")
def search_vulnerable():
    query = request.args.get("q", "")
    return f"<h1>Results for: {query}</h1>"   # attacker injects <script>


# ✅ SAFE — escape HTML special characters before rendering
from markupsafe import escape

@app.route("/search")
def search_safe():
    query = escape(request.args.get("q", ""))  # < > & " ' all escaped
    return f"<h1>Results for: {query}</h1>"


# ✅ Also enforce input length and character whitelist
import re

def validate_username(username: str) -> bool:
    """Only allow alphanumeric + underscore, max 30 chars."""
    return bool(re.match(r"^[a-zA-Z0-9_]{1,30}$", username))

print(validate_username("maureen_w"))  # True
print(validate_username("<script>"))   # False


/Code Example 4 — Secure Session Management./

python
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # strong random key

# When setting a cookie, always use Secure + HttpOnly flags:
app.config.update(
    SESSION_COOKIE_SECURE   = True,   # only sent over HTTPS
    SESSION_COOKIE_HTTPONLY = True,   # not accessible by JavaScript
    SESSION_COOKIE_SAMESITE = "Lax",  # CSRF protection
    PERMANENT_SESSION_LIFETIME = 1800  # session expires in 30 minutes
)

# Regenerate session ID after login to prevent session fixation
@app.route("/login", methods=["POST"])
def login():
    # ... verify credentials ...
    session.clear()                       # clear old session data
    session["user_id"] = authenticated_user.id
    return redirect("/dashboard")


/Code Example 5 — Security Logging./
  
python
import logging
import datetime

# Configure a security log file
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log_failed_login(username, ip_address):
    logging.warning(f"FAILED LOGIN | user={username} | ip={ip_address}")

def log_access(user_id, resource):
    logging.info(f"ACCESS | user={user_id} | resource={resource}")

def log_suspicious(description):
    logging.critical(f"SUSPICIOUS ACTIVITY | {description}")

# Usage
log_failed_login("admin", "192.168.1.55")
log_suspicious("Multiple failed logins from 192.168.1.55 in 60 seconds")
