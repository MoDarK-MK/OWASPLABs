"""
SSRF Lab 20: Complex Multi-Stage SSRF
Difficulty: 4 (Expert)
Points: 150

Description:
Complex SSRF requiring multiple stages for exploitation.
"""

from flask import Flask, request
import requests
import json

app = Flask(__name__)

SERVICE_REGISTRY = {
    'auth': 'http://auth-service:5000',
    'database': 'http://db-service:5432',
    'cache': 'http://cache-service:6379',
}

@app.route('/')
def index():
    """
    VULNERABLE: Multi-stage SSRF chain
    
    Attack Flow:
    Stage 1: Enumerate services
    /?service=auth&endpoint=/health
    
    Stage 2: Get service details
    /?service=database&endpoint=/config
    
    Stage 3: Extract credentials
    /?service=cache&endpoint=/admin/users
    
    Stage 4: Privilege escalation
    /?service=auth&endpoint=/admin/elevate&param=user_id=1
    
    Flag: FLAG{ssrf_complex_multi_stage_020}
    """
    service = request.args.get('service', '')
    endpoint = request.args.get('endpoint', '')
    content = None
    error = None
    
    if service and endpoint:
        try:
            if service not in SERVICE_REGISTRY:
                error = "Unknown service"
            else:
                url = SERVICE_REGISTRY[service] + endpoint
                response = requests.get(url, timeout=5)
                content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Multi-Stage SSRF Lab</h1>
        <form method="GET">
            <select name="service">
                <option value="">Select Service</option>
                <option value="auth">Auth Service</option>
                <option value="database">Database Service</option>
                <option value="cache">Cache Service</option>
            </select>
            <input type="text" name="endpoint" placeholder="Endpoint" size="40" value="{endpoint}">
            <button>Access</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
        <hr>
        <p><strong>Available Services:</strong></p>
        <ul>
            <li>auth: /health, /config, /users, /admin/elevate</li>
            <li>database: /health, /config, /users, /secrets</li>
            <li>cache: /health, /admin/users, /admin/keys</li>
        </ul>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return json.dumps({'status': 'healthy', 'version': '1.0'})

@app.route('/config')
def config():
    return json.dumps({'db_host': 'localhost', 'db_user': 'admin', 'db_pass': 'AdminP@ss'})

@app.route('/users')
def users():
    return json.dumps({'users': ['admin', 'user', 'guest']})

@app.route('/secrets')
def secrets():
    return json.dumps({'api_key': 'sk_live_1234567890', 'secret': 'FLAG{found_secret}'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
