"""
XSS Lab 8: CSS-based XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via CSS
Points: 75

Description:
XSS vulnerability through CSS expressions and behavior.
CSS can be used to execute JavaScript in certain contexts.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 8: CSS-based XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 8: CSS-based XSS</h1>
            <p>This lab has XSS vulnerability in CSS processing.</p>
            
            <form action="/style" method="GET">
                <input type="text" name="color" placeholder="Enter color (e.g., red)" value="red">
                <button type="submit">Apply Style</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_css_based_008}</p>
        </body>
    </html>
    """

@app.route('/style', methods=['GET'])
def style():
    """Apply user-provided CSS"""
    color = request.args.get('color', 'red')
    
    # VULNERABLE: User input directly in style tag
    html = f"""
    <html>
        <head>
            <title>Style Preview</title>
            <style>
                /* VULNERABLE: User input in CSS */
                body {{ background-color: {color}; }}
            </style>
        </head>
        <body>
            <h1>Styled Page</h1>
            <p>This page has a dynamic background color.</p>
            
            <h3>Alternative Vulnerabilities:</h3>
            <div>
                <!-- VULNERABLE: User input in style attribute -->
                <div style="color: {color};">Colored text</div>
            </div>
            
            <h3>Payload Examples:</h3>
            <ul>
                <li><code>red; --var: }};background:url("javascript:alert('XSS')")</code></li>
                <li><code>expression(alert('XSS'))</code> (IE only)</li>
                <li><code>red; }body{{ background: url('javascript:alert(\"XSS\")') }}</code></li>
                <li><code>#f00; }*{{ xss:expression(alert('XSS')) }}</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5008)
