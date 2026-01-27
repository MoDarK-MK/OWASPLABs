"""
IDOR Lab 12: Vertical Privilege Escalation
Difficulty: 3 (Advanced)
Points: 100

Description:
Access higher privilege level resources.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

ADMIN_RECORDS = {
    'user_001': {'role': 'user', 'data': 'User dashboard'},
    'admin_001': {'role': 'admin', 'data': 'System configuration: DB host=internal.server'},
    'admin_002': {'role': 'admin', 'data': 'API keys and secrets stored here'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .warning { background: red; color: white; padding: 10px; }
    </style>
</head>
<body>
    <h1>Dashboard</h1>
    <div>
        <p><strong>Role:</strong> {{ record.role }}</p>
        <p><strong>Data:</strong> {{ record.data }}</p>
    </div>
    {% if 'admin' in record.role %}
    <div class="warning">Admin Access Detected!</div>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Vertical privilege escalation
    
    Attack Vector:
    /?id=admin_001 (user accesses admin resources)
    
    Flag: FLAG{idor_vertical_escalation_012}
    """
    record_id = request.args.get('id', 'user_001')
    record = ADMIN_RECORDS.get(record_id, {'role': 'unknown', 'data': 'Not found'})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, record=record)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
