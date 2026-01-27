"""
IDOR Lab 9: Nested Resource IDOR
Difficulty: 2 (Intermediate)
Type: IDOR
Points: 75

Description:
Nested resources vulnerable to IDOR.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

PROJECTS = {
    '1': {
        'id': '1', 'name': 'Project A',
        'files': {
            '1': {'name': 'report.pdf', 'owner': 'alice'},
            '2': {'name': 'secret.txt', 'owner': 'alice'},
        }
    },
    '2': {
        'id': '2', 'name': 'Project B',
        'files': {
            '1': {'name': 'code.py', 'owner': 'bob'},
            '2': {'name': 'credentials.json', 'owner': 'bob'},
        }
    },
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>File Details</h1>
    <p><strong>Project:</strong> {{ project_id }}</p>
    <p><strong>File:</strong> {{ file_name }}</p>
    <p><strong>Owner:</strong> {{ owner }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Nested IDOR in project files
    
    Attack Vector:
    /?project=2&file=2 (access Bob's credentials file)
    
    Flag: FLAG{idor_nested_resource_009}
    """
    project_id = request.args.get('project', '1')
    file_id = request.args.get('file', '1')
    
    project = PROJECTS.get(project_id, {})
    files = project.get('files', {})
    file_info = files.get(file_id, {'name': 'Not Found', 'owner': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, project_id=project_id, file_name=file_info['name'], owner=file_info['owner'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
