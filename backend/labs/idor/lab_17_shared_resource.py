"""
IDOR Lab 17: Shared Resource IDOR
Difficulty: 3 (Advanced)
Points: 100

Description:
IDOR in shared resource access.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

SHARED_DOCS = {
    'shared_1': {'id': 'shared_1', 'name': 'Team Notes', 'owner': 'alice', 'content': 'General team information'},
    'shared_2': {'id': 'shared_2', 'name': 'Passwords', 'owner': 'bob', 'content': 'Admin passwords: root:toor', 'shared_with': ['charlie']},
    'shared_3': {'id': 'shared_3', 'name': 'API Docs', 'owner': 'charlie', 'content': 'Internal API documentation'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Shared Document</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Shared Document</h1>
    <p><strong>Name:</strong> {{ doc.name }}</p>
    <p><strong>Owner:</strong> {{ doc.owner }}</p>
    <p><strong>Content:</strong></p>
    <p>{{ doc.content }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Access shared documents without proper checks
    
    Attack Vector:
    /?doc=shared_2 (access Bob's password document)
    
    Flag: FLAG{idor_shared_resource_017}
    """
    doc_id = request.args.get('doc', 'shared_1')
    doc = SHARED_DOCS.get(doc_id, {'name': 'Not Found', 'owner': '', 'content': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, doc=doc)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
