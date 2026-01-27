"""
IDOR Lab 3: Predictable Invoice Numbers
Difficulty: 1 (Beginner)
Type: IDOR
Points: 50

Description:
Invoice numbers follow predictable pattern.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

INVOICES = {
    '2024001': {'id': '2024001', 'amount': '1000', 'customer': 'Acme Corp', 'status': 'Paid'},
    '2024002': {'id': '2024002', 'amount': '2500', 'customer': 'Tech Ltd', 'status': 'Pending'},
    '2024003': {'id': '2024003', 'amount': '500', 'customer': 'StartUp Inc', 'status': 'Overdue'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Invoice</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .invoice { border: 1px solid black; padding: 20px; width: 500px; }
        table { width: 100%; }
        td { padding: 5px; }
    </style>
</head>
<body>
    <h1>Invoice Details</h1>
    <div class="invoice">
        <table>
            <tr><td><strong>Invoice ID:</strong></td><td>{{ invoice.id }}</td></tr>
            <tr><td><strong>Customer:</strong></td><td>{{ invoice.customer }}</td></tr>
            <tr><td><strong>Amount:</strong></td><td>\${{ invoice.amount }}</td></tr>
            <tr><td><strong>Status:</strong></td><td>{{ invoice.status }}</td></tr>
        </table>
    </div>
    <p><small>Flag: FLAG{idor_predictable_invoice_003}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Predictable invoice numbers
    
    Attack Vector:
    /?inv=2024001, /?inv=2024002, /?inv=2024004 (predict next)
    
    Flag: FLAG{idor_predictable_invoice_003}
    """
    inv_id = request.args.get('inv', '2024001')
    invoice = INVOICES.get(inv_id, {'id': inv_id, 'customer': 'Unknown', 'amount': '0', 'status': 'Not Found'})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, invoice=invoice)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
