"""
CSRF Lab 18: NULL Origin
Difficulty: 3 (Advanced)
Points: 100

Description:
Null origin accepted for CSRF validation.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Action</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        button { padding: 8px 15px; background: #e83e8c; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Perform Action</h1>
    <form method="POST" action="/do-action">
        <input type="hidden" name="token" value="{{ token }}">
        <button type="submit">Execute</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/do-action', methods=['POST'])
def do_action():
    """
    VULNERABLE: Null origin accepted
    
    Attack Vector:
    Request from sandboxed iframe (null origin)
    
    Flag: FLAG{csrf_null_origin_018}
    """
    origin = request.headers.get('Origin', '')
    token = request.form.get('token', '')
    
    # Accepts null origin (from sandbox)
    if token and (origin == '' or origin is None or 'localhost' in origin):
        return """
        <html>
            <body>
                <h2>Action Executed</h2>
            </body>
        </html>
        """
    return "Rejected"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
