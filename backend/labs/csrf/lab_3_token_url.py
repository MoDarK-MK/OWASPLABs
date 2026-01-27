"""
CSRF Lab 3: Token in URL Parameter
Difficulty: 1 (Beginner)
Type: CSRF
Points: 50

Description:
Token placed in URL is vulnerable to exposure.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Delete Account</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        button { padding: 8px 15px; background: #dc3545; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Delete Account</h1>
    <form method="GET" action="/delete">
        <input type="hidden" name="token" value="{{ token }}">
        <p>Are you sure you want to delete your account?</p>
        <button type="submit">Delete Account</button>
    </form>
    <p><small>Flag: FLAG{csrf_token_in_url_003}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/delete')
def delete():
    """
    VULNERABLE: Token in URL parameters
    
    Attack Vector:
    GET /delete?token=any_token (tokens not properly validated)
    
    Flag: FLAG{csrf_token_in_url_003}
    """
    token = request.args.get('token', '')
    
    # Weak: Just checks if token exists
    if token:
        return """
        <html>
            <body>
                <h2>Account Deleted</h2>
                <p>Your account has been permanently deleted.</p>
            </body>
        </html>
        """
    return "Invalid token"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
