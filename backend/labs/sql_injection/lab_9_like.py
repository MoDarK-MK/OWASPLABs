"""
SQL Injection Lab 9: LIKE Clause SQL Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection in LIKE clause search.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_9.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS articles 
                      (id INTEGER PRIMARY KEY, title TEXT, content TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO articles VALUES (1, 'Secret Article', 'Hidden content')")
    cursor.execute("INSERT OR IGNORE INTO articles VALUES (2, 'Public Article', 'Public content')")
    conn.commit()
    conn.close()

init_db()

@app.route('/search')
def search():
    """
    VULNERABLE: LIKE clause SQL injection
    
    Attack Vector:
    /search?q=a' OR '1'='1
    /search?q=% (wildcard to get all)
    /search?q=' OR 1=1 --
    
    LIKE uses pattern matching, but still vulnerable to injection
    
    Flag: FLAG{sql_injection_like_009}
    """
    query = request.args.get('q', '')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: LIKE clause injection
        sql = f"SELECT * FROM articles WHERE title LIKE '%{query}%'"
        cursor.execute(sql)
        articles = cursor.fetchall()
        
        result = ""
        if articles:
            for article in articles:
                result += f"<p><strong>{article[1]}</strong><br>{article[2]}</p>"
        else:
            result = "No articles found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Article Search</h1>
        <form method="GET">
            <input type="text" name="q" placeholder="Search" value="{query}">
            <button>Search</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
