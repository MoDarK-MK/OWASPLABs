"""
IDOR Lab 19: API Version IDOR
Difficulty: 4 (Expert)
Points: 150

Description:
IDOR via different API versions or deprecated endpoints.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

ACCOUNTS = {
    'v1': {
        '101': {'id': '101', 'owner': 'alice', 'balance': 1000, 'private': False},
        '102': {'id': '102', 'owner': 'bob', 'balance': 2000, 'private': False},
    },
    'v2': {
        '101': {'id': '101', 'owner': 'alice', 'balance': 1000},
        '102': {'id': '102', 'owner': 'bob', 'balance': 2000},
    },
    'v3': {
        '101': {'id': '101', 'owner': 'alice', 'balance': 1000, 'account_type': 'checking'},
        '102': {'id': '102', 'owner': 'bob', 'balance': 2000, 'account_type': 'savings'},
    },
    'deprecated': {
        '101': {'id': '101', 'owner': 'alice', 'balance': 1000, 'ssn': '123-45-6789', 'full_data': True},
        '102': {'id': '102', 'owner': 'bob', 'balance': 2000, 'ssn': '987-65-4321', 'full_data': True},
    },
}

@app.route('/api/<version>/account/<account_id>')
def get_account(version, account_id):
    """
    VULNERABLE: Different API versions expose different data
    v3 and deprecated versions expose sensitive info without checks
    
    Attack Vector:
    /api/v3/account/102 (access other user's account)
    /api/deprecated/account/102 (access SSN and full data)
    
    Flag: FLAG{idor_api_version_019}
    """
    version_data = ACCOUNTS.get(version)
    
    if not version_data:
        return jsonify({'error': 'Invalid API version'}), 404
    
    account = version_data.get(account_id)
    
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    return jsonify(account)

@app.route('/')
def index():
    return '''
    <html>
    <body>
    <h1>API Version IDOR Lab</h1>
    <p>Try accessing different API versions:</p>
    <ul>
        <li>/api/v1/account/101 (basic info)</li>
        <li>/api/v2/account/102 (standard info)</li>
        <li>/api/v3/account/102 (with account type)</li>
        <li>/api/deprecated/account/102 (full data with SSN)</li>
    </ul>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
