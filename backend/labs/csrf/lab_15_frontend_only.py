"""
CSRF Lab 15: Frontend-Only Validation
Difficulty: 3 (Advanced)
Points: 100

Description:
CSRF validation only on frontend, not backend.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Safe Form</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #ffc107; color: black; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Update Account</h1>
    <form method="POST" action="/account" onsubmit="return validateCSRF()">
        <input type="hidden" id="token" name="token" value="{{ token }}">
        <input type="text" name="username" placeholder="Username" required>
        <button type="submit">Update</button>
    </form>
    <script>
        function validateCSRF() {
            var token = document.getElementById('token').value;
            return token.length > 0; // Frontend only
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/account', methods=['POST'])
def update_account():
    """
    VULNERABLE: Frontend validation only
    
    Attack Vector:
    POST /account without token (backend doesn't check)
    
    Flag: FLAG{csrf_frontend_only_015}
    """
    username = request.form.get('username', '')
    token = request.form.get('token', '')
    
    # No validation - accepts any request
    return f"""
    <html>
        <body>
            <h2>Account Updated</h2>
            <p>Username: {username}</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
