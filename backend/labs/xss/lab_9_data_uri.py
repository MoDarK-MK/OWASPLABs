"""
XSS Lab 9: Data URI XSS
Difficulty: 3 (Advanced)
Type: Reflected XSS via Data URI
Points: 100

Description:
XSS using data: URI scheme with embedded HTML/JavaScript.
Can bypass certain filters that only block javascript: protocol.
"""

from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 9: Data URI XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 9: Data URI XSS</h1>
            <p>This lab is vulnerable to Data URI based XSS attacks.</p>
            
            <form action="/view" method="GET">
                <input type="text" name="content" placeholder="Enter content to display" value="Hello">
                <button type="submit">View</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_data_uri_009}</p>
        </body>
    </html>
    """

@app.route('/view', methods=['GET'])
def view():
    """View user-provided content via data URI"""
    content = request.args.get('content', 'Hello')
    
    # VULNERABLE: User input in data URI
    html = f"""
    <html>
        <head>
            <title>Content Viewer</title>
        </head>
        <body>
            <h1>Content Preview</h1>
            
            <!-- VULNERABLE: data URI with unescaped user input -->
            <iframe src="data:text/html,<h1>{content}</h1>" width="100%" height="300"></iframe>
            
            <h3>Alternative Vulnerable Endpoints:</h3>
            <p>Image with data URI:</p>
            <img src="data:text/html,{content}" />
            
            <h3>Payload Examples:</h3>
            <ul>
                <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><code>&lt;body onload=alert('XSS')&gt;</code></li>
            </ul>
            
            <h3>Base64 Encoded Payloads:</h3>
            <ul>
                <li>Payload encoded: <code>{base64.b64encode(b"<script>alert('XSS')</script>").decode()}</code></li>
                <li>Data URI format: <code>data:text/html;base64,{base64.b64encode(b"<script>alert('XSS')</script>").decode()}</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5009)
