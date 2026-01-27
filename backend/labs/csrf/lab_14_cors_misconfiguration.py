"""
CSRF Lab 14: CORS Misconfiguration
Difficulty: 3 (Advanced)
Points: 100

Description:
CORS allows requests from any origin.
"""

from flask import Flask, request, render_template_string, jsonify
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>API Data</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>User Data</h1>
    <button onclick="fetchData()">Get Data</button>
    <div id="result"></div>
    <script>
        function fetchData() {
            fetch('/api/user-data').then(r => r.json()).then(d => {
                document.getElementById('result').textContent = JSON.stringify(d);
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/user-data', methods=['GET', 'POST', 'OPTIONS'])
def user_data():
    """
    VULNERABLE: Overly permissive CORS
    
    Attack Vector:
    CORS request from evil.com
    
    Flag: FLAG{csrf_cors_misconfiguration_014}
    """
    # Dangerous: Allows any origin
    origin = request.headers.get('Origin', '*')
    
    response = jsonify({
        'user': 'admin',
        'email': 'admin@example.com',
        'role': 'administrator'
    })
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
