"""
IDOR Lab 16: Batch Operations IDOR
Difficulty: 3 (Advanced)
Points: 100

Description:
IDOR in batch operation endpoints.
"""

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

COMMENTS = {
    '1': {'id': '1', 'text': 'Great post!', 'author': 'alice'},
    '2': {'id': '2', 'text': 'I disagree', 'author': 'bob'},
    '3': {'id': '3', 'text': 'Thanks!', 'author': 'charlie'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Batch Delete</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Delete Comments</h1>
    <form method="POST" action="/batch-delete">
        <input type="text" name="ids" placeholder="IDs (comma separated)" required>
        <button type="submit">Delete</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/batch-delete', methods=['POST'])
def batch_delete():
    """
    VULNERABLE: Batch delete without authorization
    
    Attack Vector:
    POST /batch-delete with ids=1,2,3
    
    Flag: FLAG{idor_batch_operations_016}
    """
    ids = request.form.get('ids', '').split(',')
    deleted = []
    
    for comment_id in ids:
        if comment_id in COMMENTS:
            deleted.append(comment_id)
    
    return jsonify({'deleted': deleted, 'count': len(deleted)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
