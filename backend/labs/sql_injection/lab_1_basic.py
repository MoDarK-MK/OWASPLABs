"""
SQL Injection Lab 1: Basic SQL Injection
Difficulty: 1 (Beginner)
Points: 50

Description:
Basic SQL injection in login form.
"""

from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_1.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'secret123')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password')")
    conn.commit()
    conn.close()

init_db()

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>SQL Injection Lab 1</title></head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button>Login</button>
    </form>
    {% if result %}
        <p>{{ result }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    VULNERABLE: Direct string concatenation in SQL query
    
    Attack Vector:
    username: admin' --
    password: (anything)
    
    Or:
    username: ' OR '1'='1
    password: (anything)
    
    Query becomes: SELECT * FROM users WHERE username='' OR '1'='1' AND password=''
    
    Flag: FLAG{sql_injection_basic_001}
    """
    result = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # VULNERABLE: Direct string concatenation
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                result = f"Login successful! Welcome {user[1]}"
            else:
                result = "Login failed"
            
            conn.close()
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
