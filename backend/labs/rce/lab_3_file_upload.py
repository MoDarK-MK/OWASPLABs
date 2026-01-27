"""
RCE Lab 3: File Upload RCE
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through insecure file upload.
"""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RCE Lab 3</title></head>
<body>
    <h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button>Upload</button>
    </form>
    {% if msg %}
        <p>{{ msg }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Uploads Python files and executes them
    
    Attack Vector:
    Upload a .py file containing malicious code
    File gets executed automatically
    
    Flag: FLAG{rce_file_upload_003}
    """
    msg = None
    
    if request.method == 'POST':
        file = request.files.get('file')
        
        if file:
            filename = file.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            # VULNERABLE: Execute uploaded Python files
            if filename.endswith('.py'):
                try:
                    with open(filepath) as f:
                        exec(f.read())
                    msg = f"File {filename} executed"
                except Exception as e:
                    msg = f"Error: {str(e)}"
            else:
                msg = f"File {filename} uploaded"
    
    return render_template_string(TEMPLATE, msg=msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
