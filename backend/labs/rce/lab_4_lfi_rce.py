"""
RCE Lab 4: Local File Inclusion (LFI) to RCE
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through Local File Inclusion.
"""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RCE Lab 4</title></head>
<body>
    <h1>Page Viewer</h1>
    <form method="GET">
        <input type="text" name="page" placeholder="page.txt">
        <button>View</button>
    </form>
    <pre>{% if content %}{{ content }}{% endif %}</pre>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: LFI allows including Python files with code
    
    Attack Vector:
    /?page=../../../../tmp/shell.phtml
    Create a .phtml file containing PHP/Python code
    Access it through LFI to execute
    
    Flag: FLAG{rce_lfi_004}
    """
    page = request.args.get('page', 'index.txt')
    content = None
    
    try:
        # VULNERABLE: No path traversal protection
        filepath = os.path.join('/app', page)
        
        if os.path.exists(filepath):
            with open(filepath) as f:
                content = f.read()
                
                # VULNERABLE: Execute Python files
                if filepath.endswith('.py'):
                    exec(content)
        else:
            content = "File not found"
    except Exception as e:
        content = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, content=content)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
