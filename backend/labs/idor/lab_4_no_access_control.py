"""
IDOR Lab 4: No Access Control Check
Difficulty: 1 (Beginner)
Type: IDOR
Points: 50

Description:
No verification if user owns the resource.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

DOCUMENTS = {
    '101': {'id': '101', 'name': 'Q1 Report', 'owner': 'alice', 'content': 'Quarterly report with financials...'},
    '102': {'id': '102', 'name': 'Strategic Plan', 'owner': 'bob', 'content': 'Confidential 5-year strategy...'},
    '103': {'id': '103', 'name': 'Budget Proposal', 'owner': 'charlie', 'content': 'Next year budget allocation...'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Document</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .doc { border: 1px solid #ccc; padding: 15px; }
    </style>
</head>
<body>
    <h1>Document Viewer</h1>
    <div class="doc">
        <p><strong>Document:</strong> {{ doc.name }}</p>
        <p><strong>Owner:</strong> {{ doc.owner }}</p>
        <p><strong>Content:</strong></p>
        <p>{{ doc.content }}</p>
    </div>
    <p><small>Flag: FLAG{idor_no_access_control_004}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: No ownership verification
    
    Attack Vector:
    /?doc=102 (access Bob's document without authentication)
    
    Flag: FLAG{idor_no_access_control_004}
    """
    doc_id = request.args.get('doc', '101')
    doc = DOCUMENTS.get(doc_id, {'id': doc_id, 'name': 'Not Found', 'owner': '', 'content': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, doc=doc)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
