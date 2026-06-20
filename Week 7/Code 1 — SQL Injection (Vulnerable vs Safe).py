#  VULNERABLE — user input directly in query string
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


#  SAFE — parameterized query (prepared statement)
def login_safe(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))  # values passed separately
    return cursor.fetchone()
# No matter what the user types, it is treated as data, never as SQL code.
