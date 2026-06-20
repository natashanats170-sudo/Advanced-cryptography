#  VULNERABLE — raw user input reflected back in HTML (XSS)
from flask import request

@app.route("/search")
def search_vulnerable():
    query = request.args.get("q", "")
    return f"<h1>Results for: {query}</h1>"   # attacker injects <script>


#  SAFE — escape HTML special characters before rendering
from markupsafe import escape

@app.route("/search")
def search_safe():
    query = escape(request.args.get("q", ""))  # < > & " ' all escaped
    return f"<h1>Results for: {query}</h1>"


#  Also enforce input length and character whitelist
import re

def validate_username(username: str) -> bool:
    """Only allow alphanumeric + underscore, max 30 chars."""
    return bool(re.match(r"^[a-zA-Z0-9_]{1,30}$", username))

print(validate_username("maureen_w"))  # True
print(validate_username("<script>"))   # False
