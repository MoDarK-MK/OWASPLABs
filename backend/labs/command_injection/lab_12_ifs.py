"""
Command Injection Lab 12: IFS (Internal Field Separator)
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Using IFS to bypass space filtering.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>URL Encoder</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>URL Encoder</h1>
    <form method="GET">
        <input type="text" name="text" placeholder="Enter text" value="{{ text }}">
        <button type="submit">Encode</button>
    </form>
    {% if output %}
    <h3>Result:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable IFS bypass
    
    Attack Vector:
    /?text=test${IFS}whoami
    /?text=test${IFS}id
    
    Flag: FLAG{cmd_injection_ifs_012}
    """
    text = request.args.get('text', '')
    output = ''
    
    if text:
        try:
            # VULNERABLE: IFS can replace spaces
            cmd = f"echo '{text}' | od -An -tx1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, text=text, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
