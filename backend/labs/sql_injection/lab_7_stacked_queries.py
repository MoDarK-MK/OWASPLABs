"""
SQL Injection Lab 7: Stacked Queries SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection allowing multiple query execution.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_7.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS data 
                      (id INTEGER PRIMARY KEY, value TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO data VALUES (1, 'Secret')")
    conn.commit()
    conn.close()

init_db()

@app.route('/query')
def query():
    """
    VULNERABLE: Stacked queries SQL injection
    
    Attack Vector:
    /query?sql=1; DROP TABLE data;
    /query?sql=1; INSERT INTO data VALUES (2, 'Hacked');
    /query?sql=1; CREATE TABLE secrets (key TEXT);
    
    Note: SQLite in Python by default doesn't allow stacked queries
    This lab simulates it by allowing multiple statements
    
    Flag: FLAG{sql_injection_stacked_queries_007}
    """
    sql = request.args.get('sql', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # VULNERABLE: executescript allows multiple statements
        cursor = conn.executescript(f"SELECT * FROM data WHERE id={sql}")
        results = cursor.fetchall()
        
        result = ""
        for row in results:
            result += f"<p>{row}</p>"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Query Executor</h1>
        <form method="GET">
            <input type="text" name="sql" placeholder="SQL ID" value="{sql}">
            <button>Execute</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
