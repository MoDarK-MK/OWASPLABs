"""
XSS Lab 6: SVG-based XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via SVG
Points: 75

Description:
XSS vulnerability in SVG elements and attributes.
SVG is valid HTML and can execute JavaScript through various event handlers.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 6: SVG-based XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 6: SVG-based XSS</h1>
            <p>This lab processes SVG data that can be exploited for XSS.</p>
            
            <form action="/render" method="GET">
                <input type="text" name="svg" placeholder="Enter SVG data">
                <button type="submit">Render SVG</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_svg_based_006}</p>
        </body>
    </html>
    """

@app.route('/render', methods=['GET'])
def render():
    """Render user-provided SVG"""
    svg_data = request.args.get('svg', '<circle cx="50" cy="50" r="40" fill="blue">')
    
    # VULNERABLE: SVG directly rendered without sanitization
    html = f"""
    <html>
        <head>
            <title>SVG Renderer</title>
        </head>
        <body>
            <h1>SVG Preview</h1>
            
            <!-- VULNERABLE: Unsanitized SVG rendering -->
            <svg width="300" height="300" xmlns="http://www.w3.org/2000/svg">
                {svg_data}
            </svg>
            
            <h3>Payload Examples:</h3>
            <ul>
                <li><code>&lt;circle onload="alert('XSS')" r="40"&gt;</code></li>
                <li><code>&lt;text onload="alert('XSS')"&gt;Text&lt;/text&gt;</code></li>
                <li><code>&lt;animate onload="alert('XSS')"&gt;</code></li>
                <li><code>&lt;image href="javascript:alert('XSS')"&gt;</code></li>
                <li><code>&lt;foreignObject onload="alert('XSS')"&gt;</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5006)
