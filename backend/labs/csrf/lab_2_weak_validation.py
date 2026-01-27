"""
CSRF Lab 2: Weak Token Validation
Difficulty: 1 (Beginner)
Type: CSRF
Points: 50

Description:
Token exists but validation is weak or bypassable.
"""

from flask import Flask, request, render_template_string, session
import secrets

app = Flask(__name__)
app.secret_key = 'csrf_key_456'

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #28a745; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Change Password</h1>
    <form method="POST" action="/change-password">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="password" name="old_password" placeholder="Old Password" required>
        <input type="password" name="new_password" placeholder="New Password" required>
        <button type="submit">Change Password</button>
    </form>
    <p><small>Flag: FLAG{csrf_weak_validation_002}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    session['csrf_token'] = 'token123'  # Weak: Static token
    return render_template_string(TEMPLATE, csrf_token=session.get('csrf_token', ''))

@app.route('/change-password', methods=['POST'])
def change_password():
    """
    VULNERABLE: Weak token validation (static token)
    
    Attack Vector:
    POST /change-password with csrf_token=token123
    
    Flag: FLAG{csrf_weak_validation_002}
    """
    token = request.form.get('csrf_token', '')
    old_pwd = request.form.get('old_password', '')
    new_pwd = request.form.get('new_password', '')
    
    # Weak validation - token is always the same
    if token == 'token123':
        return f"""
        <html>
            <body>
                <h2>Password Changed</h2>
                <p>Old: {old_pwd}</p>
                <p>New: {new_pwd}</p>
                <a href="/">Back</a>
            </body>
        </html>
        """
    return "Invalid token"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
