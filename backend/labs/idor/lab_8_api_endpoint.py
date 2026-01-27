"""
IDOR Lab 8: API Endpoint IDOR
Difficulty: 2 (Intermediate)
Type: IDOR
Points: 75

Description:
API endpoints vulnerable to IDOR.
"""

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

USERS_DB = {
    '1': {'id': '1', 'name': 'Alice', 'role': 'user', 'api_key': 'key_alice_123'},
    '2': {'id': '2', 'name': 'Bob', 'role': 'admin', 'api_key': 'key_bob_456'},
    '3': {'id': '3', 'name': 'Charlie', 'role': 'user', 'api_key': 'key_charlie_789'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>API Client</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>User API</h1>
    <button onclick="getUser(1)">Get User 1</button>
    <button onclick="getUser(2)">Get User 2</button>
    <button onclick="getUser(3)">Get User 3</button>
    <div id="result"></div>
    <script>
        function getUser(id) {
            fetch('/api/user/' + id).then(r => r.json()).then(d => {
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

@app.route('/api/user/<user_id>')
def get_user(user_id):
    """
    VULNERABLE: No authorization on API endpoint
    
    Attack Vector:
    GET /api/user/2 (access admin user)
    
    Flag: FLAG{idor_api_endpoint_008}
    """
    user = USERS_DB.get(user_id, {'id': user_id, 'name': 'Not Found', 'role': '', 'api_key': ''})
    return jsonify(user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
