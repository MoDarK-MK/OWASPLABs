"""
RCE Lab 20: Complex Multi-Stage RCE
Difficulty: 4 (Expert)
Points: 150

Description:
Complex Remote Code Execution requiring multi-stage exploitation.
"""

from flask import Flask, request, jsonify
import base64
import pickle

app = Flask(__name__)

SESSION_CACHE = {}

@app.route('/stage1', methods=['POST'])
def stage1():
    """
    Stage 1: Upload encoded payload
    """
    data = request.get_json() or {}
    payload = data.get('payload', '')
    
    session_id = base64.b64encode(payload.encode()).hex()
    SESSION_CACHE[session_id] = payload
    
    return jsonify({'session': session_id})

@app.route('/stage2', methods=['POST'])
def stage2():
    """
    Stage 2: Deserialize and process
    """
    data = request.get_json() or {}
    session_id = data.get('session', '')
    
    if session_id not in SESSION_CACHE:
        return jsonify({'error': 'Invalid session'})
    
    payload = SESSION_CACHE[session_id]
    
    try:
        # Stage 2: Decode
        decoded = base64.b64decode(payload)
        # VULNERABLE: Direct unserialization
        obj = pickle.loads(decoded)
        return jsonify({'status': 'processed'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/stage3', methods=['POST'])
def stage3():
    """
    Stage 3: Execute chained payload
    
    VULNERABLE: Multi-stage exploitation
    1. Send encoded pickle payload in stage1
    2. Get session ID
    3. POST to stage2 to deserialize (triggers gadget chain)
    4. POST to stage3 to finalize execution
    
    Flag: FLAG{rce_complex_multi_stage_020}
    """
    data = request.get_json() or {}
    command = data.get('cmd', '')
    
    try:
        # VULNERABLE: Execute arbitrary command
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({'output': result.stdout + result.stderr})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/')
def index():
    return """
    <html>
    <body>
        <h1>Multi-Stage RCE Lab</h1>
        <ol>
            <li>POST to /stage1 with encoded payload</li>
            <li>POST to /stage2 with session ID to deserialize</li>
            <li>POST to /stage3 with command to execute</li>
        </ol>
        <p>Example payload construction required</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
