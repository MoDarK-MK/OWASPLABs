"""
IDOR Lab 5: Weak ID Obfuscation
Difficulty: 1 (Beginner)
Type: IDOR
Points: 50

Description:
IDs obfuscated but easily decodable.
"""

from flask import Flask, request, render_template_string
import base64

app = Flask(__name__)

ORDERS = {
    base64.b64encode(b'order_1').decode(): {'order': 'order_1', 'items': 'Laptop', 'price': '999', 'user': 'alice'},
    base64.b64encode(b'order_2').decode(): {'order': 'order_2', 'items': 'Phone', 'price': '599', 'user': 'bob'},
    base64.b64encode(b'order_3').decode(): {'order': 'order_3', 'items': 'Tablet', 'price': '399', 'user': 'charlie'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Order</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .order { background: #f0f0f0; padding: 15px; }
    </style>
</head>
<body>
    <h1>Order Details</h1>
    <div class="order">
        <p><strong>Order:</strong> {{ order.order }}</p>
        <p><strong>Items:</strong> {{ order.items }}</p>
        <p><strong>Price:</strong> \${{ order.price }}</p>
        <p><strong>User:</strong> {{ order.user }}</p>
    </div>
    <p><small>Flag: FLAG{idor_weak_obfuscation_005}</small></p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Base64 encoding is easily decodable
    
    Attack Vector:
    Decode base64 ID and modify to access other orders
    
    Flag: FLAG{idor_weak_obfuscation_005}
    """
    order_id = request.args.get('id', base64.b64encode(b'order_1').decode())
    order = ORDERS.get(order_id, {'order': 'Not Found', 'items': '', 'price': '', 'user': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, order=order)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
