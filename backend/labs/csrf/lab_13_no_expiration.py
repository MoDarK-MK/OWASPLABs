"""
CSRF Lab 13: Token Expiration Not Checked
Difficulty: 3 (Advanced)
Points: 100

Description:
Tokens don't expire or expiration not validated.
"""

from flask import Flask, request, render_template_string, session
import secrets
import time

app = Flask(__name__)
app.secret_key = 'csrf_exp_test'

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Update Profile</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #17a2b8; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Update Profile</h1>
    <form method="POST" action="/profile">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="text" name="phone" placeholder="Phone" required>
        <button type="submit">Update</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    session['token_time'] = time.time()
    return render_template_string(TEMPLATE, token=token)

@app.route('/profile', methods=['POST'])
def update_profile():
    """
    VULNERABLE: No token expiration check
    
    Attack Vector:
    Reuse old token indefinitely
    
    Flag: FLAG{csrf_no_token_expiry_013}
    """
    token = request.form.get('token', '')
    phone = request.form.get('phone', '')
    
    # Only checks if token matches, not if expired
    if token == session.get('csrf_token'):
        return f"""
        <html>
            <body>
                <h2>Profile Updated</h2>
                <p>Phone: {phone}</p>
            </body>
        </html>
        """
    return "Invalid"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
