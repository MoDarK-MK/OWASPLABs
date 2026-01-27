"""
IDOR Lab 20: Complex Multi-Parameter Chain IDOR
Difficulty: 4 (Expert)
Points: 150

Description:
Complex IDOR requiring multiple parameter manipulation and privilege escalation.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

ORGANIZATIONS = {
    'org_1': {
        'id': 'org_1',
        'name': 'TechCorp',
        'admin': 'alice',
        'departments': {
            'dept_1': {
                'id': 'dept_1',
                'name': 'Engineering',
                'budget': 50000,
                'teams': {
                    'team_1': {'id': 'team_1', 'name': 'Security', 'members': 5, 'salary_pool': 500000},
                    'team_2': {'id': 'team_2', 'name': 'DevOps', 'members': 3, 'salary_pool': 300000},
                }
            },
            'dept_2': {
                'id': 'dept_2',
                'name': 'Finance',
                'budget': 25000,
                'teams': {
                    'team_3': {'id': 'team_3', 'name': 'Accounting', 'members': 8, 'salary_pool': 400000},
                }
            }
        }
    },
}

@app.route('/org/<org_id>/dept/<dept_id>/team/<team_id>')
def get_team_budget(org_id, dept_id, team_id):
    """
    VULNERABLE: Multi-level resource without authorization
    Allows accessing any organization, department, and team
    
    Attack Vector:
    Step 1: Enumerate organizations: /org/org_1/dept/dept_1/team/team_1
    Step 2: Access other departments: /org/org_1/dept/dept_2/team/team_3
    Step 3: Manipulate budget or salary data via POST (step 4)
    
    Combined with parameter tampering to escalate privileges
    
    Flag: FLAG{idor_complex_chain_020}
    """
    org = ORGANIZATIONS.get(org_id)
    
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    dept = org.get('departments', {}).get(dept_id)
    
    if not dept:
        return jsonify({'error': 'Department not found'}), 404
    
    team = dept.get('teams', {}).get(team_id)
    
    if not team:
        return jsonify({'error': 'Team not found'}), 404
    
    # Expose sensitive salary information
    return jsonify({
        'organization': org_id,
        'department': dept_id,
        'team': team,
        'budget_allocation': {
            'salary_pool': team['salary_pool'],
            'budget': dept['budget'],
            'confidential': True
        }
    })

@app.route('/org/<org_id>/dept/<dept_id>/team/<team_id>/update', methods=['POST'])
def update_team_budget(org_id, dept_id, team_id):
    """
    VULNERABLE: Update endpoint without ownership verification
    Allows escalating privileges by modifying any team's budget
    
    Attack: POST with new_salary_pool or new_members
    """
    data = request.get_json() or {}
    
    org = ORGANIZATIONS.get(org_id)
    if not org:
        return jsonify({'error': 'Not found'}), 404
    
    dept = org.get('departments', {}).get(dept_id)
    if not dept:
        return jsonify({'error': 'Not found'}), 404
    
    team = dept.get('teams', {}).get(team_id)
    if not team:
        return jsonify({'error': 'Not found'}), 404
    
    # VULNERABLE: No check if user owns this team/department
    if 'new_salary_pool' in data:
        team['salary_pool'] = data['new_salary_pool']
    
    if 'new_members' in data:
        team['members'] = data['new_members']
    
    return jsonify({'status': 'updated', 'team': team})

@app.route('/')
def index():
    return '''
    <html>
    <body>
    <h1>Complex Multi-Parameter Chain IDOR Lab</h1>
    <p>Navigate through organizational hierarchy:</p>
    <ul>
        <li>GET /org/org_1/dept/dept_1/team/team_1</li>
        <li>GET /org/org_1/dept/dept_2/team/team_3</li>
        <li>POST /org/org_1/dept/dept_1/team/team_1/update with JSON body</li>
    </ul>
    <p>Try modifying budgets and escalating privileges!</p>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=False)
