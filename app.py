from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
import time

app = Flask(__name__)
app.secret_key = 'secret123'

# ─── Database ────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp REAL NOT NULL,
            success INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def seed_users():
    users = [
        ('alice',   'alice@mail.com',   'password123'),
        ('bob',     'bob@mail.com',     'qwerty456'),
        ('charlie', 'charlie@mail.com', 'charlie2024'),
        ('diana',   'diana@mail.com',   'sunshine1'),
        ('eve',     'eve@mail.com',     'letmein99'),
        ('frank',   'frank@mail.com',   'frank@123'),
        ('grace',   'grace@mail.com',   'grace2025'),
        ('henry',   'henry@mail.com',   'henrypass'),
        ('isla',    'isla@mail.com',    'ilovecats'),
        ('jack',    'jack@mail.com',    'jackjack1'),
    ]
    conn = get_db()
    for username, email, password in users:
        try:
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashlib.sha256(password.encode()).hexdigest())
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ─── Helpers ─────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_locked_out(username):
    conn = get_db()
    now = time.time()
    window = now - 60
    count = conn.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE username = ? AND success = 0 AND timestamp > ?
    ''', (username, window)).fetchone()[0]
    conn.close()
    return count >= 5

def record_attempt(username, success):
    conn = get_db()
    conn.execute('''
        INSERT INTO login_attempts (username, timestamp, success)
        VALUES (?, ?, ?)
    ''', (username, time.time(), 1 if success else 0))
    conn.commit()
    conn.close()

def recent_fail_count(username):
    conn = get_db()
    now = time.time()
    window = now - 30
    count = conn.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE username = ? AND success = 0 AND timestamp > ?
    ''', (username, window)).fetchone()[0]
    conn.close()
    return count

def get_user_by_username_or_email(username):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        (username, username)
    ).fetchone()
    conn.close()
    return user

# ─── Routes ──────────────────────────────────────────────
@app.route('/')
def home():
    return redirect(url_for('login'))

# ── Signup ──
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email    = request.form['email'].strip()
        password = request.form['password']
        confirm  = request.form['confirm_password']

        if password != confirm:
            return render_template('signup.html', error='Passwords do not match.')
        if len(password) < 4:
            return render_template('signup.html', error='Password must be at least 4 characters.')

        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hash_password(password))
            )
            conn.commit()
            conn.close()
            return render_template('signup.html', success='Account created! You can now login.')
        except sqlite3.IntegrityError:
            return render_template('signup.html', error='Username or email already exists.')

    return render_template('signup.html')

# ── Login ──
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username         = request.form['username'].strip()
        password         = request.form['password']
        captcha_checked  = request.form.get('captcha_checked', '')

        # CAPTCHA check
        if captcha_checked != 'yes':
            return render_template('login.html',error='Please confirm you are not a robot.')

        # Lockout check
        if is_locked_out(username):
            return render_template('login.html',warning='⚠️ Account temporarily locked due to multiple failed attempts. Please try again after 1 minute.')

        # Check if user exists
        user = get_user_by_username_or_email(username)

        if not user:
            return render_template('login.html',error='No account found with this username or email.')

        # Check password
        if user['password'] != hash_password(password):
            record_attempt(username, success=False)
            fails = recent_fail_count(username)

            # IDPS Detection
            if fails >= 5:
                return render_template('login.html',warning='⚠️ Suspicious activity detected. Account locked for 1 minute.')

            return render_template('login.html',error='Incorrect password. Please try again.')

        # Success
        record_attempt(username, success=True)
        session['username'] = user['username']
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# ── Forgot Password ──
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        conn  = get_db()
        user  = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user:
            return render_template('forgot_password.html', success='If this email exists, a reset link has been sent.')
        return render_template('forgot_password.html',success='If this email exists, a reset link has been sent.')

    return render_template('forgot_password.html')

# ── Dashboard ──
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

# ── Logout ──
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Run ─────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    seed_users()
    app.run(debug=True)