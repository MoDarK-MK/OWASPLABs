"""
SSRF Lab 14: Internal API Access
Difficulty: 3 (Advanced)
Points: 100

Description:
Using SSRF to access internal APIs.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Internal API access via SSRF
    
    Attack Vector:
    /?api=http://internal-api:8080/v1/users
    /?api=http://192.168.1.100:5000/admin/users
    /?api=http://localhost:3000/api/secrets
    
    Common internal APIs:
    - http://localhost:8080/actuator (Spring Boot)
    - http://localhost:9200/_search (Elasticsearch)
    - http://localhost:5984/_all_dbs (CouchDB)
    - http://localhost:6379/info (Redis)
    
    Flag: FLAG{ssrf_internal_api_014}
    """
    api = request.args.get('api', '')
    content = None
    error = None
    
    if api:
        try:
            response = requests.get(api, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Internal API Caller</h1>
        <form method="GET">
            <input type="text" name="api" placeholder="Internal API URL" size="70" value="{api}">
            <button>Call</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/api/internal/secrets')
def internal_api():
    """Internal API endpoint"""
    return {'secret_key': 'sk_live_1234567890', 'database_url': 'postgresql://admin:password@localhost:5432/db'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
