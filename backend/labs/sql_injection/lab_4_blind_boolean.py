"""
SQL Injection Lab 4: Blind SQL Injection (Boolean-Based)
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection where no error messages are returned.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_4.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                      (id INTEGER PRIMARY KEY, username TEXT, pin TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO accounts VALUES (1, 'admin', '12345')")
    conn.commit()
    conn.close()

init_db()

@app.route('/check')
def check():
    """
    VULNERABLE: Blind boolean-based SQL injection
    
    Attack Vector:
    /check?user=admin' AND '1'='1  (returns "User exists")
    /check?user=admin' AND '1'='2  (returns "User not found")
    
    Attacker uses time delays or content differences to infer data:
    /check?user=admin' AND SUBSTR(pin,1,1)='1 (boolean based)
    
    Flag: FLAG{sql_injection_blind_boolean_004}
    """
    username = request.args.get('user', '')
    result = "User not found"
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Blind injection - returns different message based on query result
        query = f"SELECT * FROM accounts WHERE username='{username}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            result = "User exists"
        
        conn.close()
    except Exception as e:
        result = f"Error occurred"
    
    return f"""
    <html>
    <body>
        <h1>User Checker</h1>
        <form method="GET">
            <input type="text" name="user" placeholder="Username" value="{username}">
            <button>Check</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
