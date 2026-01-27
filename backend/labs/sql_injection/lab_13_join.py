"""
SQL Injection Lab 13: JOIN Clause SQL Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
SQL injection in JOIN operations.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_13.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders 
                      (id INTEGER PRIMARY KEY, product TEXT, user_id INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'John', 'FLAG{this_is_secret}')")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (1, 'Laptop', 1)")
    conn.commit()
    conn.close()

init_db()

@app.route('/orderdetail')
def orderdetail():
    """
    VULNERABLE: JOIN clause SQL injection
    
    Attack Vector:
    /orderdetail?table=users u ON o.user_id = u.id SELECT u.secret FROM users --
    /orderdetail?table=users UNION SELECT id, secret, id FROM (SELECT * FROM users) --
    
    Flag: FLAG{sql_injection_join_013}
    """
    table = request.args.get('table', 'users')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: JOIN uses unsanitized table reference
        query = f"SELECT o.id, o.product, u.name FROM orders o JOIN {table} u ON o.user_id = u.id"
        cursor.execute(query)
        orders = cursor.fetchall()
        
        result = ""
        for order in orders:
            result += f"<p>Order {order[0]}: {order[1]} (User: {order[2]})</p>"
        
        if not orders:
            result = "No orders found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Order Details</h1>
        <form method="GET">
            <input type="text" name="table" placeholder="Table" value="{table}">
            <button>View</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
