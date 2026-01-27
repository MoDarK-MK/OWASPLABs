"""
CSRF Lab 12: Predictable Tokens
Difficulty: 3 (Advanced)
Points: 100

Description:
CSRF tokens are predictable or sequential.
"""

from flask import Flask, request, render_template_string
import time

app = Flask(__name__)
token_counter = 1000

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Approve Request</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        button { padding: 8px 15px; background: #28a745; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Approve Access Request</h1>
    <form method="POST" action="/approve">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="hidden" name="request_id" value="12345">
        <button type="submit">Approve</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    global token_counter
    token_counter += 1
    return render_template_string(TEMPLATE, token=str(token_counter))

@app.route('/approve', methods=['POST'])
def approve():
    """
    VULNERABLE: Predictable sequential tokens
    
    Attack Vector:
    Guess next token (token_counter+1)
    
    Flag: FLAG{csrf_predictable_tokens_012}
    """
    token = request.form.get('token', '')
    req_id = request.form.get('request_id', '')
    
    # Token only checked if present
    if token and token.isdigit():
        return f"""
        <html>
            <body>
                <h2>Request Approved</h2>
                <p>Request {req_id} approved</p>
            </body>
        </html>
        """
    return "Invalid"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
