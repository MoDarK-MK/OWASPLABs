import os
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import jwt
import redis

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
CORS(app)

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://labs_admin:labs_password_123@localhost:5432/owasp_labs')
engine = create_engine(DATABASE_URL, echo=True)

try:
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    redis_client = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True, socket_connect_timeout=5)
    redis_client.ping()
except Exception as e:
    logger.warning(f"Redis connection failed: {e}. Continuing without Redis.")
    redis_client = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['user_id']
            request.username = payload['username']
            request.role = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health', methods=['GET'])
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not all([username, password, email]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        with engine.connect() as conn:
            conn.execute(text(
                f"INSERT INTO users (username, password, email, role, created_at) "
                f"VALUES ('{username}', '{password}', '{email}', 'user', NOW())"
            ))
            conn.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint (vulnerable by design)"""
    username = data.get('username')
    password = data.get('password')
    
    try:
        with engine.connect() as conn:

                f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
            ))
            user = result.fetchone()
        
        if user:
            token = jwt.encode(
                {
                    'user_id': user[0],
                    'username': user[1],
                    'role': user[3],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({'token': token, 'user': {'id': user[0], 'username': user[1], 'role': user[3]}}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout endpoint"""
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/labs', methods=['GET'])
@require_auth
def get_labs():
        with engine.connect() as conn:
            result = conn.execute(text(
                "SELECT id, title, category, difficulty, description, points FROM labs ORDER BY category, difficulty"
            ))
            labs = [dict(row._mapping) for row in result.fetchall()]
        
        return jsonify(labs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<int:lab_id>', methods=['GET'])
@require_auth
def get_lab(lab_id):
    """Get specific lab details"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text(
                f"SELECT * FROM labs WHERE id = {lab_id}"
            ))
        
        if lab:
            return jsonify(dict(lab._mapping)), 200
        else:
            return jsonify({'error': 'Lab not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<int:lab_id>/start', methods=['POST'])
@require_auth
def start_lab(lab_id):
    """Start a lab session"""
    try:
        with engine.connect() as conn:

            conn.execute(text(
                f"INSERT INTO lab_sessions (user_id, lab_id, started_at) "
                f"VALUES ({request.user_id}, {lab_id}, NOW())"
    try:
        with engine.connect() as conn:': 'Lab session started', 'lab_id': lab_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<int:lab_id>/submit', methods=['POST'])
@require_auth
def submit_flag(lab_id):
    """Submit flag for lab completion"""
    data = request.get_json()
    flag = data.get('flag')
    data = request.get_json()
    flag = data.get('flag')
    
    try:
        with engine.connect() as conn:
            lab = result.fetchone()
            
            if not lab:
                return jsonify({'error': 'Lab not found'}), 404
            
            correct_flag = lab[0]
            
            if flag == correct_flag:

                conn.execute(text(
                    f"UPDATE lab_sessions SET completed_at = NOW(), status = 'completed' "
                    f"WHERE user_id = {request.user_id} AND lab_id = {lab_id} AND completed_at IS NULL"
                ))

                result = conn.execute(text(f"SELECT points FROM labs WHERE id = {lab_id}"))
                points = result.fetchone()[0]
                
                return jsonify({
                    'message': 'Flag is correct!',
                    'points': points,
                    'timestamp': datetime.utcnow().isoformat()
                }), 200
            else:
                return jsonify({'success': False, 'message': 'Flag is incorrect'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<int:lab_id>/hint', methods=['GET'])
@require_auth
def get_hint(lab_id):
    """Get progressive hints for a lab"""
    hint_level = request.args.get('level', 1, type=int)
    
    try:
            result = conn.execute(text(
                f"SELECT hint_{hint_level} FROM labs WHERE id = {lab_id}"
            ))
            row = result.fetchone()
            
            if row:
                hint = row[0]
                return jsonify({'hint': hint, 'level': hint_level}), 200
            else:
                return jsonify({'error': 'No hint available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/progress', methods=['GET'])
@app.route('/api/user/progress', methods=['GET'])
@require_auth
def get_user_progress():completed' THEN 1 ELSE 0 END) as completed_labs, "
                f"SUM(CASE WHEN status = 'completed' THEN l.points ELSE 0 END) as total_points "
                f"FROM lab_sessions ls JOIN labs l ON ls.lab_id = l.id "
                f"WHERE ls.user_id = {request.user_id}"
            ))
            stats = result.fetchone()
        
        return jsonify({
            'total_labs': stats[0] or 0,
            'completed_labs': stats[1] or 0,
            'total_points': stats[2] or 0
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@require_auth
def get_user_profile():
    """Get user profile information"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text(
                f"SELECT id, username, email, role, created_at FROM users WHERE id = {request.user_id}"
            ))
            user = result.fetchone()
        
            return jsonify({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'created_at': user[4].isoformat() if user[4] else None
            }), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """Get global leaderboard"""
    limit = request.args.get('limit', 100, type=int)
    
@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():N ls.user_id = u.id "
                f"JOIN labs l ON ls.lab_id = l.id "
                f"WHERE ls.status = 'completed' "
                f"GROUP BY u.id, u.username "
                f"ORDER BY total_points DESC "
                f"LIMIT {limit}"
            ))
            leaderboard = [dict(row._mapping) for row in result.fetchall()]
        
        return jsonify(leaderboard), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500