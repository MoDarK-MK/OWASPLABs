"""
SQL Injection Lab 8: Numeric SQL Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection in numeric input fields.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_8.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders 
                      (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL)''')
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (1, 100, 500)")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (2, 100, 1000)")
    conn.commit()
    conn.close()

init_db()

@app.route('/order')
def order():
    """
    VULNERABLE: Numeric field SQL injection
    
    Attack Vector:
    /order?id=1 OR 1=1
    /order?id=1; DROP TABLE orders;
    /order?id=1 UNION SELECT 1,2,3
    
    Even though it's numeric, lacks type checking
    
    Flag: FLAG{sql_injection_numeric_008}
    """
    order_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: No type checking on numeric field
        query = f"SELECT * FROM orders WHERE id={order_id}"
        cursor.execute(query)
        order = cursor.fetchone()
        
        if order:
            result = f"Order ID: {order[0]}, User: {order[1]}, Total: ${order[2]}"
        else:
            result = "Order not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Order Viewer</h1>
        <form method="GET">
            <input type="number" name="id" placeholder="Order ID" value="{order_id}">
            <button>View</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
