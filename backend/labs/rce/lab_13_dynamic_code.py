"""
RCE Lab 13: Dynamic Code Generation RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through dynamic code generation.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Dynamic function generation from user input
    
    Attack Vector:
    POST name=test&body=return __import__('os').system('id')
    Generates: def test(): return __import__('os').system('id')
    Then executes it
    
    Flag: FLAG{rce_dynamic_code_generation_013}
    """
    result = None
    
    if request.method == 'POST':
        name = request.form.get('name', 'func')
        body = request.form.get('body', 'return 1')
        
        try:
            # VULNERABLE: Dynamic function creation from user input
            code = f"def {name}():\\n    {body}\\n"
            namespace = {}
            exec(code, namespace)
            func = namespace[name]
            result = f"Function called: {func()}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Dynamic Code Generator</h1>
        <form method="POST">
            <input type="text" name="name" placeholder="Function name">
            <textarea name="body" placeholder="Function body"></textarea>
            <button>Generate & Execute</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
