"""
XSS Lab 11: HTML5 Data Attribute XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via HTML5 Data Attributes
Points: 75

Description:
XSS through HTML5 data attributes which are then accessed via JavaScript.
Data is stored in attributes and later processed unsafely.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 11: HTML5 Data Attributes</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
                .item { background: #f5f5f5; padding: 10px; margin: 10px 0; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 11: HTML5 Data Attributes XSS</h1>
            
            <form action="/items" method="GET">
                <input type="text" name="title" placeholder="Item title">
                <button type="submit">Create Item</button>
            </form>
            
            <div id="items"></div>
            
            <script>
                function loadItems() {
                    fetch('/api/items')
                        .then(r => r.json())
                        .then(items => {
                            const container = document.getElementById('items');
                            items.forEach(item => {
                                const div = document.createElement('div');
                                div.className = 'item';
                                // VULNERABLE: data attribute with unsanitized content
                                div.setAttribute('data-info', item.title);
                                div.textContent = item.title;
                                div.onclick = function() {
                                    // VULNERABLE: Accessing data attribute and using with innerHTML
                                    alert('Info: ' + this.getAttribute('data-info'));
                                    document.body.innerHTML += '<p>Clicked: ' + this.getAttribute('data-info') + '</p>';
                                };
                                container.appendChild(div);
                            });
                        });
                }
                loadItems();
            </script>
            
            <p><strong>Flag:</strong> FLAG{xss_html5_data_011}</p>
        </body>
    </html>
    """

@app.route('/items', methods=['GET'])
def items():
    title = request.args.get('title', 'Untitled')
    return f"""
    <html>
        <head><title>Item Created</title></head>
        <body>
            <h1>Item Created</h1>
            <!-- VULNERABLE: Data stored in data attribute -->
            <div data-item="{title}" onclick="alert(this.getAttribute('data-item'))">
                Click this item
            </div>
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """

@app.route('/api/items', methods=['GET'])
def api_items():
    """Return items with unsanitized data"""
    from flask import jsonify
    return jsonify([
        {'id': 1, 'title': 'Sample Item'},
    ])

if __name__ == '__main__':
    app.run(debug=True, port=5011)
