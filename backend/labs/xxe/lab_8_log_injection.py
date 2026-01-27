"""
XXE Lab 8: XXE with Log Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE for injecting malicious content into logs.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET
import logging

app = Flask(__name__)
logging.basicConfig(filename='/tmp/app.log', level=logging.INFO)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE with log injection
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <log>&xxe;</log>
    
    File contents injected into log:
    [timestamp] - xxe: root:x:0:0:root:/root:/bin/bash
    
    Attacker can then read logs if accessible
    
    Flag: FLAG{xxe_log_injection_008}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            root = ET.fromstring(xml_input)
            content = ET.tostring(root, encoding='unicode')
            # VULNERABLE: Logging user input
            logging.info(f"Parsed XML: {content}")
            result = "XML logged"
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Log Injection via XXE</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse & Log</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
