"""
CSRF Lab 16: Token Reuse
Difficulty: 3 (Advanced)
Points: 100

Description:
Same token can be used multiple times.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Repeat Action</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        button { padding: 8px 15px; background: #6f42c1; color: white; border: none; cursor: pointer; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>Action Form</h1>
    <form id="form" method="POST" action="/action">
        <input type="hidden" name="token" value="{{ token }}">
        <button type="submit">Submit Action 1</button>
        <button type="submit" name="action" value="action2">Submit Action 2</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/action', methods=['POST'])
def perform_action():
    """
    VULNERABLE: Token can be reused multiple times
    
    Attack Vector:
    Same token used for multiple requests
    
    Flag: FLAG{csrf_token_reuse_016}
    """
    token = request.form.get('token', '')
    action = request.form.get('action', 'action1')
    
    # No token invalidation
    if token and len(token) == 32:
        return f"""
        <html>
            <body>
                <h2>Action Performed</h2>
                <p>Action: {action}</p>
            </body>
        </html>
        """
    return "Invalid"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
