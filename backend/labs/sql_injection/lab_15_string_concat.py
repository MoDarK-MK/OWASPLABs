"""
SQL Injection Lab 15: String Concatenation SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection in string concatenation operations.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_15.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs 
                      (id INTEGER PRIMARY KEY, message TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO logs VALUES (1, 'User logged in')")
    cursor.execute("INSERT OR IGNORE INTO logs VALUES (2, 'Secret flag: FLAG{found_it}')")
    conn.commit()
    conn.close()

init_db()

@app.route('/log')
def log():
    """
    VULNERABLE: String concatenation in WHERE clause
    
    Attack Vector:
    /log?prefix=User' UNION SELECT 1, 'Hacked' --
    /log?prefix=a' OR '1'='1
    /log?prefix=' || (SELECT message FROM logs WHERE id=2) || '
    
    Flag: FLAG{sql_injection_concat_015}
    """
    prefix = request.args.get('prefix', 'User')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: String concatenation in query
        query = f"SELECT * FROM logs WHERE message LIKE '{prefix}%'"
        cursor.execute(query)
        logs = cursor.fetchall()
        
        result = ""
        for log in logs:
            result += f"<p>{log[1]}</p>"
        
        if not logs:
            result = "No logs found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Log Viewer</h1>
        <form method="GET">
            <input type="text" name="prefix" placeholder="Log prefix" value="{prefix}">
            <button>Search</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
