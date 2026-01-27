"""
SQL Injection Lab 10: ORDER BY SQL Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
SQL injection in ORDER BY clause.
"""

from flask import Flask, request
import sqlite3

app = Flask(__name__)

DB_PATH = '/tmp/sqli_10.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS employees 
                      (id INTEGER PRIMARY KEY, name TEXT, salary REAL)''')
    cursor.execute("INSERT OR IGNORE INTO employees VALUES (1, 'Alice', 5000)")
    cursor.execute("INSERT OR IGNORE INTO employees VALUES (2, 'Bob', 6000)")
    cursor.execute("INSERT OR IGNORE INTO employees VALUES (3, 'Charlie', 7000)")
    conn.commit()
    conn.close()

init_db()

@app.route('/employees')
def employees():
    """
    VULNERABLE: ORDER BY clause injection
    
    Attack Vector:
    /employees?sort=name' (causes error revealing table structure)
    /employees?sort=name,salary
    /employees?sort=salary DESC; DROP TABLE employees;
    /employees?sort=name; INSERT INTO employees VALUES (99, 'Hacked', 99999);
    
    Flag: FLAG{sql_injection_order_by_010}
    """
    sort = request.args.get('sort', 'id')
    result = None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: ORDER BY uses unsanitized input
        query = f"SELECT * FROM employees ORDER BY {sort}"
        cursor.execute(query)
        employees_list = cursor.fetchall()
        
        result = "<table border='1'><tr><th>ID</th><th>Name</th><th>Salary</th></tr>"
        for emp in employees_list:
            result += f"<tr><td>{emp[0]}</td><td>{emp[1]}</td><td>${emp[2]}</td></tr>"
        result += "</table>"
        
        conn.close()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Employees</h1>
        <form method="GET">
            <input type="text" name="sort" placeholder="Sort by" value="{sort}">
            <button>Sort</button>
        </form>
        {result if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
