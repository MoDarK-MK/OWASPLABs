"""
RCE Lab 17: Gadget Chain Exploitation RCE
Difficulty: 4 (Expert)
Points: 150

Description:
Remote Code Execution through gadget chain chaining.
"""

from flask import Flask, request
import pickle
import base64

app = Flask(__name__)

class DataStore:
    def __init__(self, filename):
        self.filename = filename
    
    def __reduce__(self):
        # VULNERABLE: __reduce__ allows arbitrary code in unpickling
        return (exec, (f"__import__('os').system('id')",))

@app.route('/', methods=['POST'])
def index():
    """
    VULNERABLE: Gadget chains via magic methods
    
    Attack Vector:
    Craft pickle payload using __reduce__, __setstate__, __getstate__
    to chain method calls leading to code execution
    
    Exploit process:
    1. Create DataStore object
    2. Pickle it with malicious __reduce__
    3. Send base64 encoded payload
    4. Server unpickles and executes code
    
    Flag: FLAG{rce_gadget_chain_017}
    """
    try:
        payload = request.form.get('payload', '')
        decoded = base64.b64decode(payload)
        obj = pickle.loads(decoded)
        return f"Gadget executed"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
