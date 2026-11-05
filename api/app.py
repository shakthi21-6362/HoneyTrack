import os
from datetime import timedelta
from flask import Flask
from flask_cors import CORS
from config.settings import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY
from api.routes import api_bp

def create_app():
    """Create and configure the Flask dashboard application."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, 'dashboard', 'templates')
    static_dir = os.path.join(base_dir, 'dashboard', 'static')

    app = Flask(__name__, 
                template_folder=template_dir,
                static_folder=static_dir)
    
    app.secret_key = SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Lock down CORS: Restrict allowed origins rather than wildcard in production
    allowed_origins = os.environ.get("ALLOWED_ORIGINS")
    if allowed_origins:
        origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
        CORS(app, origins=origins_list, supports_credentials=True)
    else:
        # Default to same-origin / local origins for operator console safety
        CORS(app, origins=[
            f"http://localhost:{DASHBOARD_PORT}",
            f"http://127.0.0.1:{DASHBOARD_PORT}",
            "http://localhost",
            "http://127.0.0.1"
        ], supports_credentials=True)
    
    # ─────────────────────────────────────────────────────────────
    # Comprehensive Security Headers Middleware
    # ─────────────────────────────────────────────────────────────
    @app.after_request
    def apply_security_headers(response):
        # 1. Disable client-side caching for live telemetry
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        # 2. Anti-Clickjacking: Prevent framing in malicious iframes
        response.headers['X-Frame-Options'] = 'DENY'

        # 3. Anti-MIME Sniffing: Prevent browsers from trying to guess MIME types
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # 4. Anti-XSS Filter for older browser support
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # 5. Referrer Policy: Send referrer only on same-origin or strict cross-origin
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # 6. Permissions Policy: Disable unwanted browser hardware features
        response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(), payment=()'

        # 7. Content-Security-Policy (CSP): Tuned for Leaflet tiles, CDN scripts, and dark styles
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://*.basemaps.cartocdn.com https://*.cartocdn.com https://server.arcgisonline.com https://*.arcgisonline.com https://unpkg.com; "
            "connect-src 'self' ws: wss: https://*.basemaps.cartocdn.com https://*.cartocdn.com; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp

        return response

    # Register API blueprint
    app.register_blueprint(api_bp)
    
    # Register Auth blueprint
    from auth.auth import auth_bp
    app.register_blueprint(auth_bp)
    
    return app

def start_dashboard(host=None, port=None):
    """Entry point to start the Flask dashboard."""
    app = create_app()
    
    # Use provided host/port or fallback to config defaults
    run_host = host if host is not None else DASHBOARD_HOST
    run_port = port if port is not None else DASHBOARD_PORT
    
    # In a production environment, you would use Gunicorn or uWSGI
    # This is suitable for development/demonstration
    print(f"[API] Starting Dashboard API on {run_host}:{run_port}")
    app.run(host=run_host, port=run_port, debug=False)

if __name__ == "__main__":
    start_dashboard()
