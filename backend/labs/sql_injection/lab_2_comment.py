"""
SQL Injection Lab 2: Comment-Based SQL Injection
Difficulty: 1 (Beginner)
Points: 50

Description:
SQL injection using comment techniques.
"""

from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_2.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS products 
                      (id INTEGER PRIMARY KEY, name TEXT, price REAL)''')
    cursor.execute("INSERT OR IGNORE INTO products VALUES (1, 'Product A', 100)")
    cursor.execute("INSERT OR IGNORE INTO products VALUES (2, 'Product B', 200)")
    conn.commit()
    conn.close()

init_db()

@app.route('/product')
def product():
    """
    VULNERABLE: Comment injection to bypass WHERE clause
    
    Attack Vector:
    /product?id=1' OR '1'='1
    /product?id=1' --
    /product?id=1' #
    /product?id=1' /*
    
    Flag: FLAG{sql_injection_comment_002}
    """
    product_id = request.args.get('id', '1')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Comment character allows bypassing rest of query
        query = f"SELECT * FROM products WHERE id={product_id} AND price > 0"
        cursor.execute(query)
        product = cursor.fetchone()
        
        if product:
            result = f"Product: {product[1]}, Price: {product[2]}"
        else:
            result = "Product not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Product Viewer</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="Product ID" value="{product_id}">
            <button>Search</button>
        </form>
        <p>{result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
