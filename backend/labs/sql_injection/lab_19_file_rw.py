"""
SQL Injection Lab 19: File Read/Write SQL Injection
Difficulty: 4 (Expert)
Points: 150

Description:
SQL injection for file operations.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_19.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS content 
                      (id INTEGER PRIMARY KEY, data TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO content VALUES (1, 'File content here')")
    conn.commit()
    conn.close()

init_db()

@app.route('/file')
def file_op():
    """
    VULNERABLE: File operations via SQL injection
    
    Attack Vector:
    MySQL/MariaDB:
    /file?id=1 INTO OUTFILE '/tmp/shell.php'
    /file?id=1 LOAD_FILE('/etc/passwd')
    
    SQLite (no direct file ops but can use ATTACH):
    /file?id=1; ATTACH DATABASE '/tmp/new.db' AS new_db;
    
    Flag: FLAG{sql_injection_file_rw_019}
    """
    file_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: File path injection (simulated)
        query = f"SELECT * FROM content WHERE id={file_id}"
        cursor.execute(query)
        data = cursor.fetchone()
        
        if data:
            result = f"Content: {data[1]}"
        else:
            result = "File not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>File Reader</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="File ID" value="{file_id}">
            <button>Read</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
