from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
import sqlite3
import os
import re


from functools import wraps
from flask import session, redirect, url_for, flash

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash("Access denied. You don’t have permission.", "error")
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Use a strong, unique key

# Ensure the instance folder and DB exist
if not os.path.exists('instance'):
    os.makedirs('instance')

def init_db():
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


init_db()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Validation
        if not username or not email or not password or not role:
            flash('Please fill out all fields.', 'error')
            return render_template('register.html')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        
        conn = sqlite3.connect('instance/users.db')
        cursor = conn.cursor()
        
                # ✅ Check if email is already registered
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email already registered. Try logging in.', 'error')
            conn.close()
            return render_template('register.html')


        # ✅ These lines now get executed only if validation passes
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        
        try:
            cursor.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                           (username, email, hashed_password, role))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists. Try another one.', 'error')
        finally:
            conn.close()

    # GET request
    return render_template('register.html')


from random import randint

@app.route('/login', methods=['GET', 'POST'])
def login():
    import random  # For CAPTCHA
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        captcha_answer = request.form.get('captcha')

        num1 = session.get('captcha_num1')
        num2 = session.get('captcha_num2')

        # Check CAPTCHA
        if not captcha_answer or int(captcha_answer) != (num1 + num2):
            flash('Incorrect CAPTCHA answer.', 'error')
            return render_template('login.html', num1=num1, num2=num2)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            if user['is_locked']:
                flash('Account is locked due to multiple failed login attempts.', 'error')
                conn.close()
                return render_template('login.html', num1=num1, num2=num2)

            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Reset failed_attempts after successful login
                cursor.execute('UPDATE users SET failed_attempts = 0 WHERE id = ?', (user['id'],))
                conn.commit()

                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                conn.close()

                flash('Login successful!', 'success')
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                # Increment failed_attempts
                attempts = user['failed_attempts'] + 1
                is_locked = 1 if attempts >= 3 else 0
                cursor.execute('UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?',
                               (attempts, is_locked, user['id']))
                conn.commit()
                conn.close()

                if is_locked:
                    flash('Account locked due to 3 failed attempts.', 'error')
                else:
                    flash(f'Invalid credentials. Attempt {attempts}/3.', 'error')
        else:
            flash('Invalid email or password.', 'error')
            conn.close()

        return render_template('login.html', num1=num1, num2=num2)

    # Generate CAPTCHA
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['captcha_num1'] = num1
    session['captcha_num2'] = num2
    return render_template('login.html', num1=num1, num2=num2)





@app.route('/dashboard')
def dashboard():
    if 'username' not in session or 'role' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session['role']
    )

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' in session and session.get('role') == 'user':
        return render_template('user_dashboard.html', username=session.get('username'))
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():

    if 'user_id' in session and session.get('role') == 'admin':

        conn = get_db_connection()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.close()
        return render_template('admin_dashboard.html', users=users, username=session.get('username'))
    return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/delete_user/<int:user_id>')
@role_required('admin')
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted successfully.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unlock_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def unlock_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f"User ID {user_id} has been unlocked.", "success")
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)