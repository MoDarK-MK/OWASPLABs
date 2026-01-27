"""
SQL Injection Lab 18: Metadata Extraction SQL Injection
Difficulty: 4 (Expert)
Points: 150

Description:
SQL injection to extract database metadata.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_18.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS data 
                      (id INTEGER PRIMARY KEY, secret TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO data VALUES (1, 'Secret Data')")
    conn.commit()
    conn.close()

init_db()

@app.route('/info')
def info():
    """
    VULNERABLE: Metadata extraction via SQL injection
    
    Attack Vector:
    SQLite metadata queries:
    /info?table=data UNION SELECT name, sql FROM sqlite_master --
    /info?table=data UNION SELECT name, type FROM sqlite_master WHERE type='table' --
    
    Extract column names:
    /info?table=data UNION SELECT name, '' FROM pragma_table_info(data) --
    
    Flag: FLAG{sql_injection_metadata_018}
    """
    table = request.args.get('table', 'data')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Table name injection
        query = f"SELECT * FROM {table}"
        cursor.execute(query)
        rows = cursor.fetchall()
        
        result = ""
        for row in rows:
            result += f"<p>{row}</p>"
        
        if not rows:
            result = "No data found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Database Info</h1>
        <form method="GET">
            <input type="text" name="table" placeholder="Table name" value="{table}">
            <button>Query</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
