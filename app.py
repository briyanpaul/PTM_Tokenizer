from flask import Flask, render_template, request, jsonify, Response, abort, session, redirect, url_for
from functools import wraps
import sqlite3
import os
import base64
import time
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

# Initialize Flask app
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = 'your-secret-key-here'  # Change in production!

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'meetings.db')

# Security configuration
TEACHER_IDS = [1, 2, 3, 4, 5, 6]
TEACHER_CREDENTIALS = {
    f"teacher{i}": generate_password_hash(f"pass{i}123") for i in TEACHER_IDS
}

def init_db():
    """Initialize database tables with proper schema"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_uid TEXT NOT NULL,
                token INTEGER NOT NULL,
                teacher TEXT NOT NULL,
                completed INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assigned_tokens (
                card_uid TEXT PRIMARY KEY,
                token INTEGER UNIQUE,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS parent_info (
                card_uid TEXT PRIMARY KEY,
                parent_name TEXT,
                child_name TEXT,
                class TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Verify and add any missing columns
        cursor.execute("PRAGMA table_info(meetings)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'completed' not in columns:
            cursor.execute('ALTER TABLE meetings ADD COLUMN completed INTEGER DEFAULT 0')
        
        conn.commit()

# Initialize database at startup
with app.app_context():
    init_db()

# --- Helper Functions --- #
def get_teacher_for_token(token):
    """Get teacher assigned to a token"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT teacher FROM meetings 
            WHERE token = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (token,))
        result = cursor.fetchone()
        return result['teacher'] if result else "Unknown"

def assign_teacher(token, card_uid):
    """Assign parent to their next available teacher"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if token already assigned
        cursor.execute('SELECT 1 FROM assigned_tokens WHERE token = ?', (token,))
        if cursor.fetchone():
            raise ValueError(f"Token {token} already assigned")
        
        # Get all teachers this parent hasn't met yet
        cursor.execute('''
            SELECT teacher FROM meetings 
            WHERE card_uid = ? AND completed = 1
        ''', (card_uid,))
        met_teachers = {row['teacher'] for row in cursor.fetchall()}
        
        all_teachers = [f"Teacher {i}" for i in TEACHER_IDS]
        remaining_teachers = [t for t in all_teachers if t not in met_teachers]
        
        if not remaining_teachers:
            raise ValueError("Parent has met all teachers")
            
        # Get current teacher workloads
        cursor.execute('''
            SELECT teacher, COUNT(*) as workload 
            FROM meetings 
            WHERE completed = 0
            GROUP BY teacher
        ''')
        teacher_workloads = dict(cursor.fetchall())
        
        # Find available teachers (those with no current meetings)
        available_teachers = [t for t in remaining_teachers if teacher_workloads.get(t, 0) == 0]
        
        if available_teachers:
            # Assign to first available teacher
            return available_teachers[0]
        else:
            # If no teachers available, assign to teacher with lightest workload
            return min(remaining_teachers, key=lambda t: teacher_workloads.get(t, 0))

def log_auth_action(teacher_id, action):
    """Record authentication events"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO auth_logs (teacher_id, action)
            VALUES (?, ?)
        ''', (teacher_id, action))
        conn.commit()

def generate_confirmation_token(meeting_id):
    """Generate one-time confirmation token"""
    return base64.b64encode(f"confirm-{meeting_id}".encode()).decode()

# --- Security Decorators --- #
def teacher_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            if 'teacher_credentials' in session:
                try:
                    creds = base64.b64decode(session['teacher_credentials']).decode('utf-8')
                    username, password = creds.split(':', 1)
                    auth = type('', (), {'username': username, 'password': password})()
                except:
                    pass
        
        if not auth or not check_teacher_credentials(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def check_teacher_credentials(username, password):
    """Verify teacher credentials"""
    if username not in TEACHER_CREDENTIALS:
        return False
    return check_password_hash(TEACHER_CREDENTIALS[username], password)

def authenticate():
    """Send basic auth challenge"""
    return Response(
        'Please login with valid teacher credentials',
        401,
        {'WWW-Authenticate': 'Basic realm="Teacher Dashboard"'}
    )

def validate_teacher_id(teacher_id):
    """Ensure teacher ID is valid"""
    if not teacher_id:
        return False
    return teacher_id.isdigit() and int(teacher_id) in TEACHER_IDS

# --- Routes --- #

@app.route('/')
def dashboard():
    """Main dashboard view"""
    return render_template('dashboard.html')

@app.route('/teacher/login', methods=['GET', 'POST'])
def teacher_login():
    """Teacher login page"""
    if request.method == 'POST':
        teacher_id = request.form.get('teacher_id')
        password = request.form.get('password')
        
        if not teacher_id or not password:
            return render_template('teacher_login.html', error="All fields are required")
        
        if not validate_teacher_id(teacher_id):
            return render_template('teacher_login.html', error="Invalid teacher ID")
        
        session['teacher_credentials'] = base64.b64encode(
            f"teacher{teacher_id}:{password}".encode()
        ).decode()
        
        return redirect(url_for('teacher_dashboard', id=teacher_id))
    
    return render_template('teacher_login.html')

@app.route('/teacher/logout')
@teacher_auth_required
def teacher_logout():
    """Log out the current teacher"""
    auth = request.authorization
    if auth and auth.username.startswith('teacher'):
        teacher_id = auth.username.replace('teacher', '')
        log_auth_action(teacher_id, "logout")
    
    # Clear session credentials
    if 'teacher_credentials' in session:
        session.pop('teacher_credentials')
    
    # Send response that clears HTTP Basic Auth
    response = redirect(url_for('teacher_login'))
    response.headers['WWW-Authenticate'] = 'Basic realm="Teacher Dashboard"'
    response.status_code = 401
    return response

@app.route('/teacher')
@teacher_auth_required
def teacher_dashboard():
    """Teacher dashboard"""
    teacher_id = request.args.get('id')
    
    if not teacher_id:
        # Try to get teacher_id from auth if not in URL
        auth = request.authorization
        if auth and auth.username.startswith('teacher'):
            teacher_id = auth.username.replace('teacher', '')
    
    if not teacher_id:
        return redirect(url_for('teacher_login'))
    
    if not validate_teacher_id(teacher_id):
        abort(400, "Invalid teacher ID. Must be between 1-6")
    
    auth = request.authorization
    if f"teacher{teacher_id}" != auth.username:
        abort(403, "Access restricted to your own dashboard")
    
    log_auth_action(teacher_id, "login")
    return render_template('teacher.html', teacher_id=teacher_id)

@app.route('/register', methods=['GET', 'POST'])
def register_parent():
    """Handle parent registration"""
    if request.method == 'POST':
        try:
            card_uid = request.form.get('cardUID')
            parent_name = request.form.get('parentName')
            child_name = request.form.get('childName')
            class_name = request.form.get('className')
            
            if not all([card_uid, parent_name, child_name, class_name]):
                return jsonify({"status": "error", "message": "All fields are required"}), 400
                
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO parent_info 
                    (card_uid, parent_name, child_name, class)
                    VALUES (?, ?, ?, ?)
                ''', (card_uid, parent_name, child_name, class_name))
                conn.commit()
            
            return jsonify({"status": "success"})
            
        except sqlite3.IntegrityError:
            return jsonify({"status": "error", "message": "Database error"}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    return render_template('register.html')

@app.route('/api', methods=['GET'])
def api():
    """RFID API endpoint"""
    try:
        card_uid = request.args.get('cardUID')
        token = request.args.get('token')
        
        if not card_uid or not token:
            return jsonify({"status": "error", "message": "Missing parameters"}), 400
            
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check existing assignment
            cursor.execute('SELECT token FROM assigned_tokens WHERE card_uid = ?', (card_uid,))
            existing = cursor.fetchone()
            
            if existing:
                return jsonify({
                    "status": "exists",
                    "message": "Card already registered",
                    "card_uid": card_uid,
                    "existing_token": existing['token'],
                    "teacher": get_teacher_for_token(existing['token'])
                })
            
            # Validate token
            cursor.execute('SELECT 1 FROM assigned_tokens WHERE token = ?', (token,))
            if cursor.fetchone():
                return jsonify({
                    "status": "error",
                    "message": f"Token {token} already in use"
                }), 400
            
            # Assign teacher using fair system
            teacher = assign_teacher(token, card_uid)
            
            # Record assignment
            cursor.execute('''
                INSERT INTO assigned_tokens (card_uid, token)
                VALUES (?, ?)
            ''', (card_uid, token))
            
            # Log meeting
            cursor.execute('''
                INSERT INTO meetings (card_uid, token, teacher, completed)
                VALUES (?, ?, ?, 0)
            ''', (card_uid, token, teacher))
            
            # Get parent info if available
            cursor.execute('''
                SELECT parent_name, child_name FROM parent_info
                WHERE card_uid = ?
            ''', (card_uid,))
            parent_info = cursor.fetchone()
            
            conn.commit()
        
        response_data = {
            "status": "success",
            "token": token,
            "teacher": teacher,
            "card_uid": card_uid
        }
        
        if parent_info:
            response_data.update({
                "parent_name": parent_info[0],
                "child_name": parent_info[1]
            })
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/parent_info', methods=['GET'])
def get_parent_info():
    """Get parent information for a card UID"""
    card_uid = request.args.get('cardUID')
    if not card_uid:
        abort(400, "Missing cardUID parameter")
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT parent_name, child_name FROM parent_info 
            WHERE card_uid = ?
        ''', (card_uid,))
        result = cursor.fetchone()
        
    if not result:
        return jsonify({"status": "not_found"})
    
    return jsonify(dict(result))

@app.route('/updates')
def updates():
    """Server-Sent Events endpoint for real-time updates"""
    def event_stream():
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            last_id = 0
            
            while True:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT m.*, p.parent_name, p.child_name
                    FROM meetings m
                    LEFT JOIN parent_info p ON m.card_uid = p.card_uid
                    WHERE m.id > ? AND m.completed = 0
                    ORDER BY m.timestamp DESC
                    LIMIT 1
                ''', (last_id,))
                
                meeting = cursor.fetchone()
                if meeting:
                    last_id = meeting['id']
                    yield f"data: {json.dumps(dict(meeting))}\n\n"
                
                time.sleep(1)
    
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/api/current_meeting', methods=['GET'])
@teacher_auth_required
def get_current_meeting():
    """Get current meeting for teacher"""
    teacher_id = request.args.get('teacher_id')
    if not teacher_id:
        teacher_id = request.args.get('id')
    
    if not teacher_id:
        return jsonify({"status": "error", "message": "Teacher ID required"}), 400
    
    teacher_name = f"Teacher {teacher_id}"
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT m.*, p.parent_name, p.child_name
                FROM meetings m
                LEFT JOIN parent_info p ON m.card_uid = p.card_uid
                WHERE m.teacher = ? AND m.completed = 0
                ORDER BY m.timestamp DESC
                LIMIT 1
            ''', (teacher_name,))
            
            meeting = cursor.fetchone()
            if not meeting:
                return jsonify({"status": "no_meetings"})
                
            return jsonify(dict(meeting))
            
    except sqlite3.Error as e:
        return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500


@app.route('/api/complete_meeting', methods=['POST'])
@teacher_auth_required
def complete_meeting():
    """Mark meeting as complete and assign parent to next teacher"""
    if not request.json:
        abort(400, "JSON data required")
    
    teacher_id = request.authorization.username.replace("teacher", "")
    meeting_id = request.json.get('meeting_id')
    
    if request.json.get('confirmation_token') != generate_confirmation_token(meeting_id):
        abort(400, "Invalid confirmation token")
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get current meeting details
            cursor.execute('''
                SELECT m.card_uid, m.token FROM meetings m
                WHERE m.id = ?
            ''', (meeting_id,))
            meeting = cursor.fetchone()
            
            if not meeting:
                abort(404, "Meeting not found")
            
            # Mark current meeting complete
            cursor.execute('UPDATE meetings SET completed = 1 WHERE id = ?', (meeting_id,))
            
            # Assign parent to next teacher
            try:
                next_teacher = assign_teacher(meeting['token'], meeting['card_uid'])
                cursor.execute('''
                    INSERT INTO meetings (card_uid, token, teacher, completed)
                    VALUES (?, ?, ?, 0)
                ''', (meeting['card_uid'], meeting['token'], next_teacher))
            except ValueError as e:
                if "has met all teachers" in str(e):
                    # Parent has completed all meetings
                    cursor.execute('''
                        DELETE FROM assigned_tokens
                        WHERE token = ?
                    ''', (meeting['token'],))
                else:
                    raise
            
            conn.commit()
            
        return jsonify({
            "status": "success",
            "message": "Meeting completed",
            "next_teacher": next_teacher if 'next_teacher' in locals() else None
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/history')
def history():
    """Display meeting history"""
    teacher_id = request.args.get('teacher_id')
    
    query = '''
        SELECT m.*, p.parent_name, p.child_name,
               CASE WHEN a.card_uid IS NOT NULL THEN 1 ELSE 0 END as is_active
        FROM meetings m
        LEFT JOIN parent_info p ON m.card_uid = p.card_uid
        LEFT JOIN assigned_tokens a ON m.card_uid = a.card_uid
    '''
    
    if teacher_id:
        query += f" WHERE m.teacher = 'Teacher {teacher_id}'"
    
    query += " ORDER BY m.timestamp DESC"
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            meetings = conn.cursor().execute(query).fetchall()
        
        return render_template('history.html', meetings=meetings)
        
    except Exception as e:
        return render_template('error.html', error=str(e)), 500

@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    """Verify teacher credentials"""
    auth = request.authorization
    if not auth or not check_teacher_credentials(auth.username, auth.password):
        abort(401)
    return jsonify({"status": "valid"})

@app.route('/admin/reset_db', methods=['POST'])
def reset_db():
    """Reset the entire database (for development only)"""
    try:
        init_db()
        return jsonify({"status": "success", "message": "Database reset successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/add_missing_columns', methods=['POST'])
def add_missing_columns():
    """Add any missing columns to existing tables"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # Check and add missing columns to meetings table
            cursor.execute("PRAGMA table_info(meetings)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'completed' not in columns:
                cursor.execute('ALTER TABLE meetings ADD COLUMN completed INTEGER DEFAULT 0')
            
            conn.commit()
        
        return jsonify({"status": "success", "message": "Verified database schema"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ... [Keep all your other existing routes unchanged] ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
