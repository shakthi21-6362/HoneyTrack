import os
from flask import Flask
from flask_cors import CORS
from config.settings import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY
from api.routes import api_bp

def create_app():
    """Create and configure the Flask dashboard application."""
    # Define paths relative to this file
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, 'dashboard', 'templates')
    static_dir = os.path.join(base_dir, 'dashboard', 'static')

    app = Flask(__name__, 
                template_folder=template_dir,
                static_folder=static_dir)
    
    app.secret_key = SECRET_KEY
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Enable CORS for API access
    CORS(app)
    
    # Disable cache for live telemetry and dashboard UI
    @app.after_request
    def add_no_cache_headers(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
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
