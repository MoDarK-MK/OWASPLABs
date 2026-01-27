"""
IDOR Lab 7: Parameter Tampering
Difficulty: 2 (Intermediate)
Type: IDOR
Points: 75

Description:
Multiple parameters allow lateral movement.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

ACCOUNTS = {
    ('alice', '1001'): {'user': 'alice', 'account': '1001', 'balance': '5000', 'ssn': '123-45-6789'},
    ('bob', '1002'): {'user': 'bob', 'account': '1002', 'balance': '8500', 'ssn': '987-65-4321'},
    ('charlie', '1003'): {'user': 'charlie', 'account': '1003', 'balance': '3200', 'ssn': '555-55-5555'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Account</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Account Details</h1>
    <p><strong>User:</strong> {{ account.user }}</p>
    <p><strong>Account:</strong> {{ account.account }}</p>
    <p><strong>Balance:</strong> \${{ account.balance }}</p>
    <p><strong>SSN:</strong> {{ account.ssn }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Multiple parameters without proper checks
    
    Attack Vector:
    /?user=bob&account=1002 (change user/account parameters)
    
    Flag: FLAG{idor_parameter_tampering_007}
    """
    user = request.args.get('user', 'alice')
    account = request.args.get('account', '1001')
    
    account_data = ACCOUNTS.get((user, account), {'user': user, 'account': account, 'balance': '0', 'ssn': 'N/A'})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, account=account_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
