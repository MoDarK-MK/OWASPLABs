"""
XSS Lab 1: Reflected XSS - Basic
Difficulty: 1 (Beginner)
Type: Reflected XSS
Points: 50

Description:
This lab demonstrates basic reflected XSS vulnerability.
User input is directly reflected in the HTML response without any sanitization.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable template - directly reflects user input
VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
</head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: {{ search_query }}</p>
    <p>Showing results...</p>
</body>
</html>
"""

@app.route('/search', methods=['GET'])
def search():
    """
    Vulnerable endpoint that reflects user input directly
    
    Attack Vector:
    GET /search?q=<img src=x onerror=alert('XSS')>
    
    Flag: FLAG{xss_reflected_basic_001}
    """
    search_query = request.args.get('q', '')
    
    # VULNERABLE: User input directly rendered in HTML
    return f"""
    <html>
        <head><title>Search</title></head>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {search_query}</p>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.route('/api/search', methods=['GET'])
def api_search():
    """
    API endpoint returning JSON with unsanitized input
    
    Attack Vector:
    GET /api/search?q=");alert('XSS');//
    
    Then execute via JavaScript: JSON.parse(response) in vulnerable context
    """
    search_query = request.args.get('q', '')
    
    # VULNERABLE: No sanitization on API response
    return {
        'query': search_query,
        'results': [],
        'status': 'success'
    }

@app.route('/')
def index():
    """Home page with search form"""
    return """
    <html>
        <head>
            <title>XSS Lab 1: Reflected XSS - Basic</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; }
            </style>
        </head>
        <body>
            <h1>Lab 1: Reflected XSS - Basic</h1>
            <p>This lab has a simple reflected XSS vulnerability.</p>
            
            <h3>Try to trigger XSS:</h3>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Enter search term">
                <button type="submit">Search</button>
            </form>
            
            <h3>Payload Hints:</h3>
            <ul>
                <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
            </ul>
            
            <h3>Lab Info:</h3>
            <p><strong>Flag:</strong> FLAG{xss_reflected_basic_001}</p>
            <p><strong>Difficulty:</strong> Beginner</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True, port=5001)
