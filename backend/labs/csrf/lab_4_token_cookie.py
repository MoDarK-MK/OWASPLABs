"""
CSRF Lab 4: Token in Cookie
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
Token stored in cookie can be read and exploited.
"""

from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Transfer Money</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #ffc107; color: black; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Transfer Money</h1>
    <form method="POST" action="/transfer">
        <input type="text" name="recipient" placeholder="Recipient" required>
        <input type="number" name="amount" placeholder="Amount" required>
        <button type="submit">Transfer</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    response = make_response(render_template_string(TEMPLATE))
    response.set_cookie('csrf_token', secrets.token_hex(16))
    return response

@app.route('/transfer', methods=['POST'])
def transfer():
    """
    VULNERABLE: Token in cookie, no validation
    
    Attack Vector:
    POST /transfer (browser sends cookie automatically)
    
    Flag: FLAG{csrf_token_in_cookie_004}
    """
    recipient = request.form.get('recipient', '')
    amount = request.form.get('amount', '')
    
    return f"""
    <html>
        <body>
            <h2>Transfer Successful</h2>
            <p>Transferred {amount} to {recipient}</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
