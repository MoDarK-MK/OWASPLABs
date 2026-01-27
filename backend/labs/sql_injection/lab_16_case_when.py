"""
SQL Injection Lab 16: CASE/WHEN SQL Injection
Difficulty: 4 (Expert)
Points: 150

Description:
SQL injection using CASE/WHEN statements.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_16.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS roles 
                      (id INTEGER PRIMARY KEY, user_id INTEGER, role TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO roles VALUES (1, 100, 'admin')")
    cursor.execute("INSERT OR IGNORE INTO roles VALUES (2, 101, 'user')")
    conn.commit()
    conn.close()

init_db()

@app.route('/role')
def role():
    """
    VULNERABLE: CASE/WHEN injection for privilege escalation
    
    Attack Vector:
    /role?uid=100) UNION SELECT 1,101, (CASE WHEN 1=1 THEN 'admin' ELSE 'user' END) --
    /role?uid=100) CASE WHEN (SELECT COUNT(*) FROM roles)>0 THEN 1 ELSE 0 END --
    
    Flag: FLAG{sql_injection_case_when_016}
    """
    user_id = request.args.get('uid', '100')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: CASE clause with unsanitized input
        query = f"SELECT id, user_id, role FROM roles WHERE user_id={user_id}"
        cursor.execute(query)
        role_data = cursor.fetchone()
        
        if role_data:
            result = f"User {role_data[1]} has role: {role_data[2]}"
        else:
            result = "User not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Role Checker</h1>
        <form method="GET">
            <input type="text" name="uid" placeholder="User ID" value="{user_id}">
            <button>Check</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
