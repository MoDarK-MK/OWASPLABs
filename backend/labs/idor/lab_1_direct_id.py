"""
IDOR Lab 1: Direct User ID Access
Difficulty: 1 (Beginner)
Type: IDOR
Points: 50

Description:
User profiles accessible by direct ID in URL.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Mock user database
USERS = {
    '1': {'id': '1', 'name': 'Alice', 'email': 'alice@example.com', 'phone': '123-456-7890'},
    '2': {'id': '2', 'name': 'Bob', 'email': 'bob@example.com', 'phone': '098-765-4321'},
    '3': {'id': '3', 'name': 'Charlie', 'email': 'charlie@example.com', 'phone': '555-1234'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .profile { border: 1px solid #ddd; padding: 20px; }
        input { width: 300px; padding: 8px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>User Profile</h1>
    <div class="profile">
        <p><strong>ID:</strong> {{ user.id }}</p>
        <p><strong>Name:</strong> {{ user.name }}</p>
        <p><strong>Email:</strong> {{ user.email }}</p>
        <p><strong>Phone:</strong> {{ user.phone }}</p>
    </div>
    <p><a href="/?id=1">Profile 1</a> | <a href="/?id=2">Profile 2</a> | <a href="/?id=3">Profile 3</a></p>
    <p><small>Flag: FLAG{idor_direct_id_001}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Direct ID access without authorization check
    
    Attack Vector:
    /?id=2 (access other user profiles)
    
    Flag: FLAG{idor_direct_id_001}
    """
    user_id = request.args.get('id', '1')
    user = USERS.get(user_id, {'id': user_id, 'name': 'Unknown', 'email': 'N/A', 'phone': 'N/A'})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, user=user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
