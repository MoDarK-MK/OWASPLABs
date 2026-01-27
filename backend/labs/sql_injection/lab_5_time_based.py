"""
SQL Injection Lab 5: Time-Based Blind SQL Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection using time delays as inference channel.
"""

from flask import Flask, request
import sqlite3
import time

app = Flask(__name__)

DB_PATH = '/tmp/sqli_5.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS items 
                      (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO items VALUES (1, 'Item1', 'HIDDEN_DATA')")
    conn.commit()
    conn.close()

init_db()

@app.route('/item')
def item():
    """
    VULNERABLE: Time-based blind SQL injection
    
    Attack Vector:
    /item?id=1; SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM items) ELSE 0 END;
    /item?id=1' AND SLEEP(5) --
    /item?id=1' AND IF(1=1, SLEEP(5), 0) --
    
    In SQLite: Use time.sleep() simulation
    /item?id=1' OR (SELECT COUNT(*) FROM items WHERE name='Item1') > 0 --
    
    Flag: FLAG{sql_injection_time_based_005}
    """
    item_id = request.args.get('id', '1')
    result = None
    start_time = time.time()
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Time-based blind injection
        query = f"SELECT * FROM items WHERE id={item_id}"
        cursor.execute(query)
        item = cursor.fetchone()
        
        elapsed = time.time() - start_time
        
        if item:
            # Simulate time delay for TRUE condition
            time.sleep(0.1)
            result = "Item found"
        else:
            result = "Item not found"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Item Finder</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="Item ID" value="{item_id}">
            <button>Find</button>
        </form>
        <p>{result}</p>
        <p><small>Response time: {time.time() - start_time:.3f}s</small></p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
