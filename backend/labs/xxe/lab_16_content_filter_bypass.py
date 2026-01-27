"""
XXE Lab 16: XXE Content Filter Bypass
Difficulty: 4 (Expert)
Points: 150

Description:
XXE bypassing content/tag filters.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

FILTER_KEYWORDS = ['ENTITY', 'SYSTEM', 'DOCTYPE', 'file://']

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Filter bypass for XXE
    
    Attack Vector:
    Filter checks for keywords but can be bypassed:
    
    Case variation:
    <!entity instead of <!ENTITY
    <!ENTITY vs <!Entity vs <!eNtItY
    
    Encoding:
    <!&#69;NTITY (Entity with HTML entity for E)
    
    Whitespace:
    <!EN&#10;TITY
    <!EN&#13;TITY
    
    Unicode:
    Ent&#1456;ity
    
    Flag: FLAG{xxe_content_filter_bypass_016}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        # VULNERABLE: Simple keyword filtering
        is_filtered = any(keyword.lower() in xml_input.lower() for keyword in FILTER_KEYWORDS)
        
        if is_filtered:
            error = "Blocked keywords detected"
        else:
            try:
                root = ET.fromstring(xml_input)
                result = ET.tostring(root, encoding='unicode')
            except Exception as e:
                error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>XXE Content Filter Bypass</h1>
        <p>Filter blocks: {', '.join(FILTER_KEYWORDS)}</p>
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
    app.run(host='0.0.0.0', port=5016, debug=False)
