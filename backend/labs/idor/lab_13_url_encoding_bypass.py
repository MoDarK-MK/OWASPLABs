"""
IDOR Lab 13: URL Encoding Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
URL encoding bypasses weak filters.
"""

from flask import Flask, request, render_template_string, unquote

app = Flask(__name__)

SENSITIVE_FILES = {
    'file1': {'name': 'public.txt', 'content': 'Public information'},
    '../../../etc/passwd': {'name': 'passwd', 'content': 'root:x:0:0:root:/root'},
    '../../secrets.txt': {'name': 'secrets.txt', 'content': 'API_KEY=super_secret_123'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Content</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .content { background: #f0f0f0; padding: 10px; }
    </style>
</head>
<body>
    <h1>File Viewer</h1>
    <div class="content">
        <p><strong>File:</strong> {{ file.name }}</p>
        <p><strong>Content:</strong></p>
        <pre>{{ file.content }}</pre>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: URL encoding bypass
    
    Attack Vector:
    /?file=..%2F..%2F..%2Fetc%2Fpasswd
    
    Flag: FLAG{idor_url_encoding_bypass_013}
    """
    file_id = unquote(request.args.get('file', 'file1'))
    file_obj = SENSITIVE_FILES.get(file_id, {'name': 'Not Found', 'content': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, file=file_obj)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
