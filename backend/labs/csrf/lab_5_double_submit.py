"""
CSRF Lab 5: Double-Submit Cookie
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
Token duplicated in both cookie and form is vulnerable.
"""

from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Update Settings</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #17a2b8; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Update Settings</h1>
    <form method="POST" action="/settings">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="email" name="email" placeholder="Email" required>
        <button type="submit">Save Settings</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    response = make_response(render_template_string(TEMPLATE, token=token))
    response.set_cookie('token', token)
    return response

@app.route('/settings', methods=['POST'])
def settings():
    """
    VULNERABLE: Double-submit cookie (both readable)
    
    Attack Vector:
    POST /settings with token from cookie and form
    
    Flag: FLAG{csrf_double_submit_005}
    """
    form_token = request.form.get('token', '')
    cookie_token = request.cookies.get('token', '')
    email = request.form.get('email', '')
    
    # Only checks if they match, not if they're valid
    if form_token and form_token == cookie_token:
        return f"""
        <html>
            <body>
                <h2>Settings Updated</h2>
                <p>Email: {email}</p>
            </body>
        </html>
        """
    return "Invalid token"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
