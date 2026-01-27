"""
Command Injection Lab 19: Filter Bypass Techniques
Difficulty: 4 (Expert)
Type: Command Injection
Points: 150

Description:
Bypassing input filters and WAF protections.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Filtered Input Tool</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Filtered Input Tool</h1>
    <form method="GET">
        <input type="text" name="input" placeholder="Enter input" value="{{ input }}">
        <button type="submit">Process</button>
    </form>
    {% if output %}
    <h3>Output:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable filter bypass
    
    Attack Vector:
    /?input=<space> or case variation or encoding
    /?input=ca''t or ca\\x74
    
    Flag: FLAG{cmd_injection_filter_bypass_019}
    """
    user_input = request.args.get('input', '')
    output = ''
    
    if user_input and len(user_input) < 20:  # Simple length filter
        try:
            # VULNERABLE: Limited filter doesn't catch all bypasses
            cmd = f"echo {user_input} | wc -c"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    else:
        output = "Input too long or empty"
    
    return render_template_string(TEMPLATE, input=user_input, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
