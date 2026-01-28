"""
XSS Lab 20: Advanced WAF Bypass
Difficulty: 4 (Master)
Type: Advanced XSS with WAF Bypass
Points: 150

Description:
The application has advanced security controls (WAF-like filters).
Must use sophisticated techniques to bypass all security measures.
"""

from flask import Flask, request
import re

app = Flask(__name__)

# Advanced filter list (similar to WAF)
blocked_patterns = [
    r'<script[^>]*>',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'onclick\s*=',
    r'<iframe',
    r'<embed',
    r'<object',
]

def advanced_filter(text):
    """Advanced but still bypassable filter"""
    filtered = text
    for pattern in blocked_patterns:
        filtered = re.sub(pattern, '', filtered, flags=re.IGNORECASE)
    # Additional check
    if len(filtered) < len(text) * 0.5:  # If more than 50% removed, block
        return None
    return filtered

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 20: Advanced WAF Bypass</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                textarea { width: 100%; padding: 8px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 20: Advanced WAF Bypass (Master Level)</h1>
            <p>This is the most advanced lab. The application has multiple layers of security.</p>
            <p style="color: red;"><strong>Difficulty:</strong> Master Level - Requires advanced WAF bypass techniques</p>
            
            <form action="/secure" method="POST">
                <textarea name="input" placeholder="Try to bypass the WAF" rows="4"></textarea>
                <button type="submit">Submit</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_waf_bypass_master_020}</p>
        </body>
    </html>
    """

@app.route('/secure', methods=['POST'])
def secure():
    user_input = request.form.get('input', '')
    
    # Apply advanced filter
    filtered = advanced_filter(user_input)
    
    if filtered is None:
        return """
        <html>
            <head><title>Blocked</title></head>
            <body>
                <h1>Request Blocked by WAF</h1>
                <p>Your input triggered too many security filters.</p>
                <p><a href="/">Back</a></p>
            </body>
        </html>
        """
    
    # VULNERABLE: Even after filtering, still vulnerable to advanced techniques
    html_response = f"""
    <html>
        <head>
            <title>Processed</title>
            <script>
                // Context: Inside JavaScript
                var user_data = "{filtered}";
                console.log(user_data);
            </script>
        </head>
        <body>
            <h1>Your Input:</h1>
            <!-- Context: HTML rendering -->
            <p>{filtered}</p>
            
            <!-- Context: HTML attributes -->
            <div title="{filtered}">Hover over me</div>
            
            <h3>Advanced Bypass Techniques:</h3>
            <ul>
                <li><strong>Null Byte Injection:</strong> <code>%00&lt;script&gt;</code></li>
                <li><strong>Unicode Escape:</strong> <code>\\u003cscript\\u003e</code></li>
                <li><strong>HTML Comments:</strong> <code>&lt;!--&gt;&lt;script&gt;</code></li>
                <li><strong>Mixed Encoding:</strong> <code>&lt;img src=x on&#101;rror=alert('XSS')&gt;</code></li>
                <li><strong>Mutation XSS:</strong> <code>&lt;noscript&gt;&lt;svg onload=alert('XSS')&gt;</code></li>
                <li><strong>Nested Tags:</strong> <code>&lt;script&gt;&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><strong>Tag Attributes:</strong> <code>&lt;img src=x on error=alert('XSS')&gt;</code> (space in attribute)</li>
                <li><strong>Unusual Quotes:</strong> <code>&lt;img src=x onerror=alert(String.fromCharCode(88,83,83))&gt;</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5020)
