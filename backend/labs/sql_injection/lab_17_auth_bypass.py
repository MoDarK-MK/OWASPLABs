"""
SQL Injection Lab 17: Bypass Authentication with SQL Injection
Difficulty: 4 (Expert)
Points: 150

Description:
Advanced authentication bypass techniques.
"""

from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_17.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials 
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO credentials VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO credentials VALUES (2, 'user', 'pass123', 'user@example.com')")
    conn.commit()
    conn.close()

init_db()

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Advanced Auth Bypass</title></head>
<body>
    <h1>Secure Login</h1>
    <form method="POST">
        <input type="text" name="user" placeholder="Username">
        <input type="password" name="pass" placeholder="Password">
        <button>Login</button>
    </form>
    {% if msg %}
        <p>{{ msg }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    VULNERABLE: Advanced authentication bypass
    
    Attack Vector:
    user: admin' --
    pass: anything
    
    user: admin' # 
    pass: anything
    
    user: ' OR 1=1 --
    pass: anything
    
    user: admin' AND email LIKE '%'
    pass: anything
    
    Flag: FLAG{sql_injection_auth_bypass_017}
    """
    msg = None
    
    if request.method == 'POST':
        user = request.form.get('user', '')
        pwd = request.form.get('pass', '')
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # VULNERABLE: Comments allow bypassing password check
            query = f"SELECT * FROM credentials WHERE username='{user}' AND password='{pwd}'"
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                msg = f"Login successful! Welcome {result[1]}"
            else:
                msg = "Invalid credentials"
            
            conn.close()
        except Exception as e:
            msg = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, msg=msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
