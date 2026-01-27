"""
RCE Lab 16: Prototype Pollution RCE
Difficulty: 4 (Expert)
Points: 150

Description:
Remote Code Execution through Prototype Pollution.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

class User:
    def __init__(self, data):
        for key, value in data.items():
            setattr(self, key, value)

@app.route('/user', methods=['POST'])
def create_user():
    """
    VULNERABLE: Prototype pollution in object construction
    
    Attack Vector:
    POST /user
    {"name": "test", "__proto__": {"isAdmin": true}}
    {"__class__": "__main__.User", "__init__": {...}}
    
    Flag: FLAG{rce_prototype_pollution_016}
    """
    data = request.get_json() or {}
    
    try:
        # VULNERABLE: Direct setattr without filtering
        user = User(data)
        return jsonify({'status': 'created'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/')
def index():
    return """
    <html>
    <body>
        <h1>Prototype Pollution Lab</h1>
        <p>POST to /user with JSON payload containing __proto__ or __init__</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
