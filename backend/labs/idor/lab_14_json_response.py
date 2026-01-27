"""
IDOR Lab 14: JSON Response IDOR
Difficulty: 3 (Advanced)
Points: 100

Description:
IDOR in JSON API responses.
"""

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

TRANSACTIONS = {
    '1001': {'id': '1001', 'user': 'alice', 'amount': '100', 'status': 'completed', 'card_last4': '1234'},
    '1002': {'id': '1002', 'user': 'bob', 'amount': '5000', 'status': 'completed', 'card_last4': '5678'},
    '1003': {'id': '1003', 'user': 'charlie', 'amount': '250', 'status': 'pending', 'card_last4': '9999'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Transactions</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Transaction History</h1>
    <input type="text" id="txn_id" placeholder="Transaction ID">
    <button onclick="getTxn()">View</button>
    <div id="result"></div>
    <script>
        function getTxn() {
            var id = document.getElementById('txn_id').value;
            fetch('/api/transaction/' + id).then(r => r.json()).then(d => {
                document.getElementById('result').textContent = JSON.stringify(d);
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/transaction/<txn_id>')
def get_transaction(txn_id):
    """
    VULNERABLE: IDOR in JSON response
    
    Attack Vector:
    GET /api/transaction/1002 (access Bob's transaction)
    
    Flag: FLAG{idor_json_response_014}
    """
    txn = TRANSACTIONS.get(txn_id, {'id': txn_id, 'user': 'unknown', 'amount': '', 'status': 'not found', 'card_last4': ''})
    return jsonify(txn)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
