#  VULNERABLE — no check that the logged-in user owns the record
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/account")
def get_account_vulnerable():
    user_id = request.args.get("id")   # attacker can pass ANY id
    record  = db.query(f"SELECT * FROM accounts WHERE id={user_id}")
    return jsonify(record)


#  SAFE — enforce ownership check
@app.route("/account")
def get_account_safe():
    current_user = get_logged_in_user()      # from session/token
    user_id      = request.args.get("id")
    if str(current_user.id) != str(user_id): # ownership check
        return jsonify({"error": "Forbidden"}), 403
    record = db.query("SELECT * FROM accounts WHERE id=?", user_id)
    return jsonify(record)
