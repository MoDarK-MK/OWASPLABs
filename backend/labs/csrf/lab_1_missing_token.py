"""
CSRF Lab 1: Missing CSRF Token
Difficulty: 1 (Beginner)
Type: CSRF
Points: 50

Description:
Application doesn't implement CSRF tokens at all.
"""

from flask import Flask, request, render_template_string, session
import secrets

app = Flask(__name__)
app.secret_key = 'csrf_key_123'

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .form-group { margin-bottom: 10px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Update Profile</h1>
    <form method="POST" action="/update">
        <div class="form-group">
            <label>Username:</label>
            <input type="text" name="username" value="{{ username }}" required>
        </div>
        <div class="form-group">
            <label>Email:</label>
            <input type="email" name="email" value="{{ email }}" required>
        </div>
        <button type="submit">Update Profile</button>
    </form>
    <p><small>Flag: FLAG{csrf_no_token_001}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE, username='user', email='user@example.com')

@app.route('/update', methods=['POST'])
def update():
    """
    VULNERABLE: No CSRF token validation
    
    Attack Vector:
    POST /update with username=hacker&email=hacker@evil.com
    
    Flag: FLAG{csrf_no_token_001}
    """
    username = request.form.get('username', '')
    email = request.form.get('email', '')
    
    return f"""
    <html>
        <body>
            <h2>Profile Updated</h2>
            <p>Username: {username}</p>
            <p>Email: {email}</p>
            <a href="/">Back</a>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
