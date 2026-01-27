"""
SSRF Lab 1: Direct URL Parameter Injection
Difficulty: 1 (Beginner)
Points: 50

Description:
Basic Server-Side Request Forgery through URL parameter.
"""

from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>SSRF Lab 1</title></head>
<body>
    <h1>Web Content Fetcher</h1>
    <form method="GET">
        <input type="text" name="url" placeholder="Enter URL">
        <button>Fetch</button>
    </form>
    {% if content %}
        <pre>{{ content }}</pre>
    {% endif %}
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Direct URL fetching without validation
    
    Attack Vector:
    /?url=http://localhost:5000/admin
    /?url=http://127.0.0.1/admin
    /?url=http://internal-service:8080/api
    
    Flag: FLAG{ssrf_direct_url_001}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: No URL validation or whitelisting
            response = requests.get(url, timeout=5)
            content = response.text[:500]
        except Exception as e:
            error = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, content=content, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
