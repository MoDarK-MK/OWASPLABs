"""
SQL Injection Lab 6: Second-Order SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection where malicious input is stored and executed later.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_6.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages 
                      (id INTEGER PRIMARY KEY, sender TEXT, content TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/save', methods=['POST'])
def save():
    """
    Stage 1: Store malicious payload
    """
    sender = request.form.get('sender', '')
    content = request.form.get('content', '')
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # VULNERABLE: Stored without sanitization
        cursor.execute("INSERT INTO messages (sender, content) VALUES (?, ?)", (sender, content))
        conn.commit()
        conn.close()
        return "Message saved"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/retrieve')
def retrieve():
    """
    VULNERABLE: Second-order SQL injection
    
    Stage 1: Post to /save with sender='admin' OR '1'='1
    Stage 2: GET /retrieve retrieves and uses stored data in another query
    
    Attack Vector:
    1. POST /save with sender="admin' --" and content="anything"
    2. GET /retrieve?name=admin' -- 
    3. The stored payload executes in the second query
    
    Flag: FLAG{sql_injection_second_order_006}
    """
    name = request.args.get('name', '')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Uses previously stored data in query
        query = f"SELECT * FROM messages WHERE sender='{name}'"
        cursor.execute(query)
        messages = cursor.fetchall()
        
        result = ""
        for msg in messages:
            result += f"<p>From: {msg[1]}, Message: {msg[2]}</p>"
        
        if not messages:
            result = "No messages found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Message System</h1>
        <h2>Save Message</h2>
        <form action="/save" method="POST">
            <input type="text" name="sender" placeholder="Sender">
            <textarea name="content" placeholder="Content"></textarea>
            <button>Save</button>
        </form>
        <h2>Retrieve Messages</h2>
        <form method="GET">
            <input type="text" name="name" placeholder="From" value="{name}">
            <button>Retrieve</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
