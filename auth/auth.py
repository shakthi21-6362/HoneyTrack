from flask import Blueprint, request, session, redirect, render_template, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging

from database.database import SessionLocal
from database.user_model import User

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

import threading
from alerts.email_alerts import send_login_notification

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        
        if not email or not password:
            flash('Please enter both email and password.')
            return render_template('login.html')

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not check_password_hash(user.password_hash, password):
                logger.warning(f"[AUTH] Failed login attempt for email: {email}")
                flash('Invalid credentials. Please verify your email and password.')
                return render_template('login.html')

            # Credentials verified
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            
            logger.info(f"[AUTH] Operator authenticated: {user.email} (ID: {user.id})")

            # Send login alert email in background thread
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            threading.Thread(
                target=send_login_notification,
                args=(user.name, user.email, client_ip),
                daemon=True
            ).start()

            # Update demo mode recipient
            try:
                from demo import set_alert_recipient
                set_alert_recipient(user.email)
            except Exception:
                pass

            return redirect('/')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An authentication error occurred. Please try again.')
        finally:
            db.close()
            
    return render_template('login.html')

@auth_bp.route('/register', methods=['POST'])
def register():
    name = (request.form.get('name') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    
    if not email or not password:
        flash('Email and password are required.')
        return render_template('login.html')

    if len(password) < 6:
        flash('Password must be at least 6 characters.')
        return render_template('login.html')

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            flash('An account with this email already exists. Please sign in.')
            return render_template('login.html')
            
        new_user = User(
            name=name or email.split('@')[0].capitalize(),
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        session['user_id'] = new_user.id
        session['user_email'] = new_user.email
        session['user_name'] = new_user.name

        logger.info(f"[AUTH] New operator registered: {new_user.email}")

        # Send welcome/login security notification email in background thread
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        threading.Thread(
            target=send_login_notification,
            args=(new_user.name, new_user.email, client_ip),
            daemon=True
        ).start()

        # Update demo mode recipient
        try:
            from demo import set_alert_recipient
            set_alert_recipient(new_user.email)
        except Exception:
            pass

        return redirect('/')
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        flash('Registration failed. Please try again.')
        return render_template('login.html')
    finally:
        db.close()

@auth_bp.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect('/login')
