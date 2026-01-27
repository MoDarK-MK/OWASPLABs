"""
Command Injection Lab 20: Advanced Chaining
Difficulty: 4 (Expert)
Type: Command Injection
Points: 150

Description:
Complex multi-stage command injection attacks.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Task Executor</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Task Executor</h1>
    <form method="GET">
        <input type="text" name="task" placeholder="Enter task name" value="{{ task }}">
        <button type="submit">Execute</button>
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
    Vulnerable advanced chaining
    
    Attack Vector:
    /?task=setup && bash -c 'cat /etc/passwd' && cleanup
    /?task=test; exec bash; echo done
    /?task=$(whoami)/test
    
    Flag: FLAG{cmd_injection_advanced_chain_020}
    """
    task = request.args.get('task', '')
    output = ''
    
    if task:
        try:
            # VULNERABLE: Complex command chaining
            cmd = f"echo 'Executing: {task}' && date && whoami"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, task=task, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
