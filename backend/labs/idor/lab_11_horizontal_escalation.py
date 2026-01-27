"""
IDOR Lab 11: Horizontal Privilege Escalation
Difficulty: 3 (Advanced)
Points: 100

Description:
Access same privilege level resources of other users.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

EMPLOYEE_RECORDS = {
    '1': {'id': '1', 'name': 'Alice', 'role': 'manager', 'salary': '50000', 'email': 'alice@company.com'},
    '2': {'id': '2', 'name': 'Bob', 'role': 'manager', 'salary': '52000', 'email': 'bob@company.com'},
    '3': {'id': '3', 'name': 'Charlie', 'role': 'manager', 'salary': '51000', 'email': 'charlie@company.com'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Record</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Employee Information</h1>
    <p><strong>Name:</strong> {{ emp.name }}</p>
    <p><strong>Role:</strong> {{ emp.role }}</p>
    <p><strong>Salary:</strong> \${{ emp.salary }}</p>
    <p><strong>Email:</strong> {{ emp.email }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Horizontal privilege escalation
    
    Attack Vector:
    /?emp=2 (manager access another manager's salary)
    
    Flag: FLAG{idor_horizontal_escalation_011}
    """
    emp_id = request.args.get('emp', '1')
    employee = EMPLOYEE_RECORDS.get(emp_id, {'name': 'Not Found', 'role': '', 'salary': '', 'email': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, emp=employee)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
