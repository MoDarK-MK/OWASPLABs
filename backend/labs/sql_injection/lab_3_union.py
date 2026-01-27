"""
SQL Injection Lab 3: UNION-Based SQL Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection using UNION to extract data from other tables.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_3.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS posts 
                      (id INTEGER PRIMARY KEY, title TEXT, content TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS secrets 
                      (id INTEGER PRIMARY KEY, secret TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO posts VALUES (1, 'Post 1', 'Content')")
    cursor.execute("INSERT OR IGNORE INTO secrets VALUES (1, 'SECRET_FLAG_HERE')")
    conn.commit()
    conn.close()

init_db()

@app.route('/post')
def post():
    """
    VULNERABLE: UNION-based SQL injection
    
    Attack Vector:
    /post?id=1 UNION SELECT id, secret, secret FROM secrets
    /post?id=1 UNION ALL SELECT 1, 2, 3 FROM secrets --
    
    Requires knowing column count and types
    
    Flag: FLAG{sql_injection_union_003}
    """
    post_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: UNION injection allows accessing other tables
        query = f"SELECT id, title, content FROM posts WHERE id={post_id}"
        cursor.execute(query)
        posts = cursor.fetchall()
        
        result = ""
        for post in posts:
            result += f"<p>ID: {post[0]}, Title: {post[1]}, Content: {post[2]}</p>"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Post Reader</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="Post ID" value="{post_id}">
            <button>Read</button>
        </form>
        {result}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
