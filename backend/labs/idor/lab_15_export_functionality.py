"""
IDOR Lab 15: IDOR in Export Functionality
Difficulty: 3 (Advanced)
Points: 100

Description:
Export functions vulnerable to IDOR.
"""

from flask import Flask, request, render_template_string, send_file
import io

app = Flask(__name__)

REPORTS = {
    '1': {'id': '1', 'name': 'Q1 Report', 'owner': 'alice', 'data': 'Q1 Results: Revenue $1M'},
    '2': {'id': '2', 'name': 'Budget Plan', 'owner': 'bob', 'data': 'Confidential budget allocation'},
    '3': {'id': '3', 'name': 'Roadmap', 'owner': 'charlie', 'data': 'Product roadmap details'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Report Export</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Export Report</h1>
    <a href="/export?report=1">Export Report 1</a>
    <a href="/export?report=2">Export Report 2</a>
    <a href="/export?report=3">Export Report 3</a>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/export')
def export_report():
    """
    VULNERABLE: Export without authorization
    
    Attack Vector:
    GET /export?report=2 (export Bob's report)
    
    Flag: FLAG{idor_export_functionality_015}
    """
    report_id = request.args.get('report', '1')
    report = REPORTS.get(report_id, {'name': 'Unknown', 'data': 'Not found'})
    
    content = f"Report: {report['name']}\n{report['data']}"
    
    return send_file(
        io.BytesIO(content.encode()),
        mimetype='text/plain',
        as_attachment=True,
        download_name=f"report_{report_id}.txt"
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
