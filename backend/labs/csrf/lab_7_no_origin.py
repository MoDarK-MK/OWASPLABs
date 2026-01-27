"""
CSRF Lab 7: No Origin Check
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
Application doesn't validate Origin header.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Add Recipient</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #e83e8c; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Add Payment Recipient</h1>
    <form method="POST" action="/add-recipient">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="text" name="name" placeholder="Name" required>
        <input type="text" name="account" placeholder="Account" required>
        <button type="submit">Add</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/add-recipient', methods=['POST'])
def add_recipient():
    """
    VULNERABLE: No Origin header validation
    
    Attack Vector:
    POST /add-recipient from any origin
    
    Flag: FLAG{csrf_no_origin_check_007}
    """
    token = request.form.get('token', '')
    name = request.form.get('name', '')
    account = request.form.get('account', '')
    
    if token:
        return f"""
        <html>
            <body>
                <h2>Recipient Added</h2>
                <p>{name}: {account}</p>
            </body>
        </html>
        """
    return "Failed"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
