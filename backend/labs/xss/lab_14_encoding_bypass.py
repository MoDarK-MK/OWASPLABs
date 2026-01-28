"""
XSS Lab 14: Filter Bypass - HTML Encoding
Difficulty: 3 (Advanced)
Type: Reflected XSS with HTML Encoding Bypass
Points: 100

Description:
The application attempts to filter XSS by looking for certain patterns.
Bypass using HTML entity encoding or double encoding.
"""

from flask import Flask, request
import html

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 14: Filter Bypass - Encoding</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 14: Filter Bypass - HTML Encoding</h1>
            <p>This lab filters certain strings but can be bypassed with encoding.</p>
            
            <form action="/encode" method="GET">
                <input type="text" name="text" placeholder="Enter text">
                <button type="submit">Process</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_encoding_bypass_014}</p>
        </body>
    </html>
    """

@app.route('/encode', methods=['GET'])
def encode():
    text = request.args.get('text', '')
    
    # VULNERABLE FILTER: Only blocks obvious patterns
    dangerous = ['<script', 'javascript:', 'onerror', 'onload']
    
    # Weak filter check
    blocked = False
    for pattern in dangerous:
        if pattern in text.lower():
            blocked = True
            break
    
    if blocked:
        # Tries to sanitize but doesn't escape output
        decoded_text = html.unescape(text)
    else:
        decoded_text = text
    
    html_response = f"""
    <html>
        <head><title>Encoded Text</title></head>
        <body>
            <h1>Result:</h1>
            <!-- VULNERABLE: No output escaping, decoded text displayed -->
            <div>{decoded_text}</div>
            
            <h3>Bypass Methods:</h3>
            <ul>
                <li>HTML Entity: <code>&amp;lt;img src=x onerror=alert('XSS')&amp;gt;</code></li>
                <li>Double Encoding: <code>&amp;amp;lt;img src=x onerror=alert('XSS')&amp;amp;gt;</code></li>
                <li>Mixed encoding: <code>&lt;img src=x on&#101;rror=alert('XSS')&gt;</code></li>
                <li>Unicode escape: <code>&lt;img src=x on\\x65rror=alert('XSS')&gt;</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5014)
