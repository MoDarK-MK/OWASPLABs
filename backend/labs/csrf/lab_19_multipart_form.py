"""
CSRF Lab 19: MultiPart Form Data
Difficulty: 4 (Expert)
Points: 150

Description:
Multipart form data submission bypasses validation.
"""

from flask import Flask, request, render_template_string
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload Document</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; display: block; margin-bottom: 10px; }
        button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Upload Document</h1>
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="hidden" name="token" value="{{ token }}">
        <input type="text" name="title" placeholder="Title" required>
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    token = secrets.token_hex(16)
    return render_template_string(TEMPLATE, token=token)

@app.route('/upload', methods=['POST'])
def upload():
    """
    VULNERABLE: Multipart form bypasses checks
    
    Attack Vector:
    Multipart submission from form without token validation
    
    Flag: FLAG{csrf_multipart_formdata_019}
    """
    token = request.form.get('token', '')
    title = request.form.get('title', '')
    file = request.files.get('file')
    
    # Weak validation
    if title:
        return f"""
        <html>
            <body>
                <h2>Upload Successful</h2>
                <p>Title: {title}</p>
            </body>
        </html>
        """
    return "Failed"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
