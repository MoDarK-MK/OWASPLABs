"""
XSS Lab 13: Filter Bypass - Case Variations
Difficulty: 3 (Advanced)
Type: Reflected XSS with Filter Bypass
Points: 100

Description:
The application has a basic filter that only blocks lowercase <script> tags.
Bypass the filter using case variations or alternative encodings.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 13: Filter Bypass - Case</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
                .warning { background: #fff3cd; padding: 10px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>Lab 13: Filter Bypass - Case Variations</h1>
            <p>This lab has a basic filter that only blocks lowercase &lt;script&gt; tags.</p>
            
            <form action="/comment" method="POST">
                <textarea name="message" placeholder="Post a comment" rows="4" cols="40"></textarea>
                <button type="submit">Post</button>
            </form>
            
            <div class="warning">
                <p><strong>Note:</strong> The application filters &lt;script&gt; tags for security.</p>
            </div>
            
            <p><strong>Flag:</strong> FLAG{xss_filter_bypass_case_013}</p>
        </body>
    </html>
    """

@app.route('/comment', methods=['POST'])
def comment():
    message = request.form.get('message', '')
    
    # VULNERABLE FILTER: Only blocks lowercase <script>
    if '<script>' in message.lower():
        # This filter only removes lowercase <script>
        filtered = message.replace('<script>', '')
    else:
        filtered = message
    
    html = f"""
    <html>
        <head><title>Comment Posted</title></head>
        <body>
            <h1>Your Comment:</h1>
            <!-- VULNERABLE: Filter bypassed with case variations -->
            <p>{filtered}</p>
            
            <h3>How to bypass this filter:</h3>
            <ul>
                <li>Use uppercase: <code>&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;</code></li>
                <li>Use mixed case: <code>&lt;ScRiPt&gt;alert('XSS')&lt;/sCrIpT&gt;</code></li>
                <li>Use alternative tags: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li>Use other event handlers: <code>&lt;body onload=alert('XSS')&gt;</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5013)
