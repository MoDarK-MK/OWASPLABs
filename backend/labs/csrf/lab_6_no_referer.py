"""
CSRF Lab 6: No Referer Check
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
Application doesn't check Referer header.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Update Bio</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        textarea { width: 400px; height: 150px; padding: 8px; }
        button { padding: 8px 15px; background: #6f42c1; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Update Bio</h1>
    <form method="POST" action="/bio">
        <input type="hidden" name="token" value="{{ token }}">
        <textarea name="bio" placeholder="Enter your bio" required></textarea>
        <button type="submit">Save Bio</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/bio', methods=['POST'])
def update_bio():
    """
    VULNERABLE: No Referer header validation
    
    Attack Vector:
    POST /bio from evil.com
    
    Flag: FLAG{csrf_no_referer_check_006}
    """
    token = request.form.get('token', '')
    bio = request.form.get('bio', '')
    
    # Token only check, ignoring origin
    if token and len(token) == 32:  # Weak validation
        return f"""
        <html>
            <body>
                <h2>Bio Updated</h2>
                <p>Bio: {bio}</p>
            </body>
        </html>
        """
    return "Invalid"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
