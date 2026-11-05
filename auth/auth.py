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
from auth.security import auth_limiter, log_admin_action

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

        # Enforce rate limiting against brute-force attacks
        is_limited, retry_after = auth_limiter.is_rate_limited(client_ip)
        if is_limited:
            logger.warning(f"[AUTH SECURITY] Rate limit triggered for IP {client_ip} on /login (lockout: {retry_after}s)")
            log_admin_action("Anonymous", "LOGIN_RATE_LIMITED", {"ip": client_ip, "retry_after": retry_after}, ip=client_ip)
            flash(f"Too many failed login attempts. Account access is temporarily locked for security. Please try again in {retry_after} seconds.")
            return render_template('login.html'), 429

        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        
        if not email or not password:
            flash('Please enter both email and password.')
            return render_template('login.html')

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not check_password_hash(user.password_hash, password):
                auth_limiter.record_attempt(client_ip)
                logger.warning(f"[AUTH] Failed login attempt for email: {email} from {client_ip}")
                log_admin_action(email or "Unknown", "LOGIN_FAILED", {"reason": "Invalid credentials", "ip": client_ip}, ip=client_ip)
                flash('Invalid credentials. Please verify your email and password.')
                return render_template('login.html')

            # Credentials verified — reset rate limiter
            auth_limiter.reset(client_ip)

            session.permanent = request.form.get('remember') == 'true'
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            
            logger.info(f"[AUTH] Operator authenticated: {user.email} (ID: {user.id})")
            log_admin_action(user.name, "LOGIN_SUCCESS", {"user_id": user.id, "email": user.email}, ip=client_ip)

            # Send login alert email in background thread
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

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if session.get('user_id'):
            return redirect('/')
        return render_template('login.html', is_register=True)

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

    # Rate limit operator registrations to prevent registration flooding
    is_limited, retry_after = auth_limiter.is_rate_limited(client_ip)
    if is_limited:
        logger.warning(f"[AUTH SECURITY] Registration rate limit triggered for IP {client_ip} (lockout: {retry_after}s)")
        flash(f"Too many registration requests. Please wait {retry_after} seconds before trying again.")
        return render_template('login.html', is_register=True), 429

    name = (request.form.get('name') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    
    if not email or not password:
        flash('Email and password are required.')
        return render_template('login.html', is_register=True)

    if len(password) < 6:
        flash('Password must be at least 6 characters.')
        return render_template('login.html', is_register=True)

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            auth_limiter.record_attempt(client_ip)
            flash('An account with this email already exists. Please sign in.')
            return render_template('login.html', is_register=True)
            
        new_user = User(
            name=name or email.split('@')[0].capitalize(),
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        session.permanent = request.form.get('remember') == 'true'
        session['user_id'] = new_user.id
        session['user_email'] = new_user.email
        session['user_name'] = new_user.name

        logger.info(f"[AUTH] New operator registered: {new_user.email}")
        log_admin_action(new_user.name, "USER_REGISTERED", {"user_id": new_user.id, "email": new_user.email}, ip=client_ip)

        # Send welcome/login security notification email in background thread
        forwarded = request.headers.get('X-Forwarded-For')
        client_ip = forwarded.split(',')[0].strip() if forwarded else request.remote_addr
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
        return render_template('login.html', is_register=True)
    finally:
        db.close()

@auth_bp.route('/logout', methods=['GET'])
def logout():
    user_name = session.get('user_name', 'Operator')
    user_email = session.get('user_email', 'unknown')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    log_admin_action(user_name, "OPERATOR_LOGOUT", {"email": user_email}, ip=client_ip)
    session.clear()
    return redirect('/login')
