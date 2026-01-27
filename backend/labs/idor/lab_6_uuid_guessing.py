"""
IDOR Lab 6: UUID Guessing
Difficulty: 2 (Intermediate)
Type: IDOR
Points: 75

Description:
UUIDs are predictable or brute-forceable.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

RESOURCES = {
    '550e8400-e29b-41d4-a716-446655440000': {'id': '550e8400-e29b-41d4-a716-446655440000', 'name': 'Resource A', 'data': 'Secret data A'},
    '550e8400-e29b-41d4-a716-446655440001': {'id': '550e8400-e29b-41d4-a716-446655440001', 'name': 'Resource B', 'data': 'Confidential data B'},
    '550e8400-e29b-41d4-a716-446655440002': {'id': '550e8400-e29b-41d4-a716-446655440002', 'name': 'Resource C', 'data': 'Secret info C'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Resource</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Resource Details</h1>
    <p><strong>Name:</strong> {{ resource.name }}</p>
    <p><strong>Data:</strong> {{ resource.data }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: UUID pattern is brute-forceable
    
    Attack Vector:
    Increment UUID suffix to find other resources
    
    Flag: FLAG{idor_uuid_guessing_006}
    """
    res_id = request.args.get('res', '550e8400-e29b-41d4-a716-446655440000')
    resource = RESOURCES.get(res_id, {'name': 'Not Found', 'data': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, resource=resource)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
