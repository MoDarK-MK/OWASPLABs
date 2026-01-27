"""
RCE Lab 10: Expression Language Injection RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through Expression Language (EL) injection.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Evaluating user input as expressions
    
    Attack Vector:
    POST expression=7+5
    POST expression=__import__('os').system('id')
    
    Note: Simplified EL-like evaluation
    
    Flag: FLAG{rce_expression_language_010}
    """
    result = None
    
    if request.method == 'POST':
        expr = request.form.get('expression', '')
        
        try:
            # VULNERABLE: Direct evaluation of expression
            result = eval(expr)
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Expression Evaluator</h1>
        <form method="POST">
            <input type="text" name="expression" placeholder="Enter expression">
            <button>Evaluate</button>
        </form>
        {f"<p>Result: {result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
