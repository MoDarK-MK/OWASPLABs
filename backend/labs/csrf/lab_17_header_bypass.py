"""
CSRF Lab 17: Custom Header Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
Custom header check can be bypassed.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>API Request</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        button { padding: 8px 15px; background: #20c997; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>API Endpoint</h1>
    <button onclick="sendRequest()">Send Request</button>
    <script>
        function sendRequest() {
            fetch('/api/secure', {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({action: 'update'})
            }).then(r => r.text()).then(d => console.log(d));
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/secure', methods=['POST'])
def secure_api():
    """
    VULNERABLE: Custom header check bypassed by form submission
    
    Attack Vector:
    Form POST without X-Requested-With header
    
    Flag: FLAG{csrf_custom_header_bypass_017}
    """
    req_with = request.headers.get('X-Requested-With', '')
    
    # Bypass: Can submit form without this header
    if req_with == 'XMLHttpRequest':
        return {'status': 'success'}
    
    # No alternative validation
    action = request.form.get('action', request.json.get('action', ''))
    
    return f"""
    <html>
        <body>
            <h2>Request Processed</h2>
            <p>Action: {action}</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
