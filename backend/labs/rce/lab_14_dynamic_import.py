"""
RCE Lab 14: Dynamic Import RCE
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through dynamic module imports.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Dynamic import of arbitrary modules
    
    Attack Vector:
    /?module=os&func=system&arg=id
    Imports: os module, calls system('id')
    
    Or simpler:
    /?module=subprocess&func=call&arg=whoami
    
    Flag: FLAG{rce_dynamic_import_014}
    """
    module_name = request.args.get('module', 'os')
    func_name = request.args.get('func', 'getcwd')
    arg = request.args.get('arg', '')
    result = None
    
    try:
        # VULNERABLE: Dynamic import and function calling
        module = __import__(module_name)
        func = getattr(module, func_name)
        
        if arg:
            result = func(arg)
        else:
            result = func()
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Module Importer</h1>
        <form method="GET">
            <input type="text" name="module" placeholder="Module name" value="{module_name}">
            <input type="text" name="func" placeholder="Function" value="{func_name}">
            <input type="text" name="arg" placeholder="Argument" value="{arg}">
            <button>Import & Call</button>
        </form>
        <p>Result: {result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
