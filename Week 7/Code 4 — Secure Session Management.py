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
