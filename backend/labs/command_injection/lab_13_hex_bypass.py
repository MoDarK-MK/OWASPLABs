"""
Command Injection Lab 13: Hex Encoding Bypass
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Using hex encoding to bypass filters.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>String Converter</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>String Converter</h1>
    <form method="GET">
        <input type="text" name="str" placeholder="Enter string" value="{{ str }}">
        <button type="submit">Convert</button>
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
    Vulnerable hex encoding bypass
    
    Attack Vector:
    /?str=\\x77\\x68\\x6f\\x61\\x6d\\x69
    
    Flag: FLAG{cmd_injection_hex_bypass_013}
    """
    text = request.args.get('str', '')
    output = ''
    
    if text:
        try:
            # VULNERABLE: Hex encoding can bypass filters
            cmd = f"echo -e '{text}' | cat"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, str=text, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
