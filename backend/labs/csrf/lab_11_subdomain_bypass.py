"""
CSRF Lab 11: Subdomain Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
Cross-subdomain CSRF vulnerability.
"""

from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Action</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #dc3545; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Admin Panel</h1>
    <form method="POST" action="/admin/action">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="text" name="action" placeholder="Action" required>
        <button type="submit">Execute</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/admin/action', methods=['POST'])
def admin_action():
    """
    VULNERABLE: Subdomain CSRF (shares cookies)
    
    Attack Vector:
    POST from subdomain.example.com if cookies are shared
    
    Flag: FLAG{csrf_subdomain_bypass_011}
    """
    token = request.form.get('token', '')
    action = request.form.get('action', '')
    
    if token:
        return f"""
        <html>
            <body>
                <h2>Action Executed</h2>
                <p>Action: {action}</p>
            </body>
        </html>
        """
    return "Unauthorized"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
