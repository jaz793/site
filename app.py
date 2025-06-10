from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, json, bcrypt

app = Flask(__name__)
CORS(app)  # Enable if frontend served elsewhere

# -- Load CAPTCHA answers from file --
with open('captcha_answers.json') as f:
    CAPTCHA_ANSWERS = json.load(f)

# -- Ensure SQLite user table exists --
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -- Util: get hashed password --
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# -- Util: check CAPTCHA --
def check_captcha(captcha_id, answer):
    correct = CAPTCHA_ANSWERS.get(captcha_id, '').strip().lower()
    return answer.strip().lower() == correct

# -- Signup endpoint --
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    captcha_id = data.get('captcha_id')
    captcha_answer = data.get('captcha_answer', '')

    if not username or not password or not captcha_id or not captcha_answer:
        return jsonify({'error': 'Missing required fields.'}), 400

    if not check_captcha(captcha_id, captcha_answer):
        return jsonify({'error': 'CAPTCHA incorrect.'}), 400

    try:
        hashed = hash_password(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Signup successful!'}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already taken.'}), 409
    except Exception as e:
        return jsonify({'error': 'Server error.'}), 500

# -- Login endpoint --
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    captcha_id = data.get('captcha_id')
    captcha_answer = data.get('captcha_answer', '')

    if not username or not password or not captcha_id or not captcha_answer:
        return jsonify({'error': 'Missing required fields.'}), 400

    if not check_captcha(captcha_id, captcha_answer):
        return jsonify({'error': 'CAPTCHA incorrect.'}), 400

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({'error': 'Invalid username or password.'}), 401

        stored_hash = row[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return jsonify({'message': 'Login successful!'}), 200
        else:
            return jsonify({'error': 'Invalid username or password.'}), 401
    except Exception as e:
        return jsonify({'error': 'Server error.'}), 500

# -- Serve CAPTCHA images --
@app.route('/static/captcha/<filename>')
def serve_captcha(filename):
    return send_from_directory('static/captcha', filename)

# -- Run the app --
if __name__ == '__main__':
    app.run(debug=True)
