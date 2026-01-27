"""
CSRF Lab 10: JSON API CSRF
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
JSON API endpoints vulnerable to CSRF.
"""

from flask import Flask, request, jsonify, render_template_string
import json

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>API Client</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>API Request</h1>
    <form method="POST" action="/api/data">
        <input type="text" name="name" placeholder="Name">
        <button type="submit">Submit</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/data', methods=['POST'])
def api_data():
    """
    VULNERABLE: JSON API without CSRF protection
    
    Attack Vector:
    POST /api/data with JSON data
    
    Flag: FLAG{csrf_json_api_010}
    """
    try:
        name = request.form.get('name') or request.json.get('name', '')
        return jsonify({'status': 'success', 'data': {'name': name}})
    except:
        return jsonify({'status': 'error'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
