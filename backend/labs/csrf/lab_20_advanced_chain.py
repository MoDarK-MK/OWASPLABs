"""
CSRF Lab 20: Advanced Chain Attack
Difficulty: 4 (Expert)
Points: 150

Description:
Multi-step CSRF attack chain.
"""

from flask import Flask, request, render_template_string, session, make_response
import secrets

app = Flask(__name__)
app.secret_key = 'csrf_advanced'

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Settings</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .step { margin-bottom: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #28a745; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Security Settings</h1>
    
    <div class="step">
        <h3>Step 1: Enable 2FA</h3>
        <form method="POST" action="/enable-2fa">
            <input type="hidden" name="token" value="{{ token }}">
            <button type="submit">Enable</button>
        </form>
    </div>
    
    <div class="step">
        <h3>Step 2: Change Email</h3>
        <form method="POST" action="/change-email">
            <input type="hidden" name="token" value="{{ token }}">
            <input type="email" name="email" placeholder="New Email" required>
            <button type="submit">Update</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    session['csrf_token'] = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=session['csrf_token'])

@app.route('/enable-2fa', methods=['POST'])
def enable_2fa():
    """Step 1 of chain"""
    token = request.form.get('token', '')
    if token == session.get('csrf_token'):
        session['2fa_enabled'] = True
        return "2FA Enabled"
    return "Failed"

@app.route('/change-email', methods=['POST'])
def change_email():
    """
    VULNERABLE: Multi-step chain exploitable
    
    Attack Vector:
    Chain both forms in single attack
    
    Flag: FLAG{csrf_advanced_chain_020}
    """
    token = request.form.get('token', '')
    email = request.form.get('email', '')
    
    # No validation after first step
    if token:
        return f"""
        <html>
            <body>
                <h2>Email Updated</h2>
                <p>New Email: {email}</p>
            </body>
        </html>
        """
    return "Failed"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
