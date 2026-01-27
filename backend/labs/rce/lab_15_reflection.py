"""
RCE Lab 15: Reflection-Based RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution using reflection/introspection.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Using reflection to call arbitrary methods
    
    Attack Vector:
    /?cls=os.system&method=system&arg=id
    Uses reflection to call methods on classes
    
    Or leverage Python's built-in classes:
    /?cls=__builtins__&method=eval&arg=malicious_code
    
    Flag: FLAG{rce_reflection_015}
    """
    cls_name = request.args.get('cls', '__builtins__')
    method = request.args.get('method', 'len')
    arg = request.args.get('arg', 'test')
    result = None
    
    try:
        # VULNERABLE: Dynamic class/method access via reflection
        if cls_name == '__builtins__':
            cls = __builtins__
        else:
            parts = cls_name.split('.')
            cls = __import__(parts[0])
            for part in parts[1:]:
                cls = getattr(cls, part)
        
        func = getattr(cls, method)
        result = func(arg) if arg else func()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Reflection Engine</h1>
        <form method="GET">
            <input type="text" name="cls" placeholder="Class" value="{cls_name}">
            <input type="text" name="method" placeholder="Method" value="{method}">
            <input type="text" name="arg" placeholder="Argument" value="{arg}">
            <button>Reflect</button>
        </form>
        <p>Result: {result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
