import logging
from flask import Flask
from flask_session import Session
# from flask_sqlalchemy import SQLAlchemy # Uncomment if using Flask-SQLAlchemy for sessions
from flask_cors import CORS

# --- Initialize Extensions ---
# db = SQLAlchemy() # Uncomment if using Flask-SQLAlchemy
sess = Session()

# --- Import Components ---
from .config import configure_flask_app, MBKAUTHE_CONFIG
from .db import init_db_pool, close_db_pool, db_pool # Import db_pool if needed elsewhere
from .routes import mbkauthe_bp
from .middleware import (
    validate_session,
    check_role_permission,
    validate_session_and_role,
    authenticate_token,
    get_user_data,
    _restore_session_from_cookie # Expose if needed externally? Usually not.
)

# --- Exports ---
# Export middleware decorators and utility functions
__all__ = [
    "validate_session",
    "check_role_permission",
    "validate_session_and_role",
    "authenticate_token",
    "get_user_data",
    "mbkauthe_bp",          # Export the blueprint
    "configure_mbkauthe",   # Export the setup function
    "db_pool",              # Export the pool if direct access is needed (use with caution)
]

# --- Setup Function ---
def configure_mbkauthe(app: Flask):
    """
    Configures and registers the mbkauthe blueprint and extensions with the Flask app.

    Args:
        app (Flask): The Flask application instance.
    """
    logger = logging.getLogger(__name__)
    logger.info("Configuring mbkauthe for Flask app...")

    # 1. Apply mbkauthe specific configurations to the Flask app
    configure_flask_app(app)

    # 2. Initialize Database Pool (if not done elsewhere)
    try:
        init_db_pool()
    except Exception as e:
        logger.error(f"Failed to initialize database pool during configure_mbkauthe: {e}")
        # Decide how to handle this - raise, log and continue?
        raise RuntimeError("Failed to initialize mbkauthe database pool") from e

    # 3. Initialize Flask-Session
    # If using SQLAlchemy backend with Flask-SQLAlchemy, ensure db = SQLAlchemy(app) is called *before* this.
    # If using manual SQLAlchemy engine, it's configured via app.config in configure_flask_app
    sess.init_app(app)
    logger.info(f"Flask-Session initialized with type: {app.config.get('SESSION_TYPE')}")

    # 4. Initialize CORS (Optional - can be done per-blueprint or globally)
    # Example: Allow CORS for the mbkauthe blueprint specifically
    # CORS(mbkauthe_bp, supports_credentials=True, origins=["*.yourdomain.com"]) # Adjust origins
    # Or apply globally: CORS(app, ...)

    # 5. Register the Blueprint
    app.register_blueprint(mbkauthe_bp)
    logger.info("mbkauthe blueprint registered.")

    # 6. Register App Teardown for DB Pool Cleanup
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        close_db_pool()
        # logger.debug("Database pool closed on app context teardown.")

    logger.info("mbkauthe configuration complete.")

# --- Example Usage (in your main Flask app file) ---
# from flask import Flask
# from mbkauthe import configure_mbkauthe
#
# app = Flask(__name__)
#
# # Load mbkautheVar from .env BEFORE calling configure_mbkauthe
# # (python-dotenv is loaded in mbkauthe.config)
#
# configure_mbkauthe(app)
#
# @app.route('/')
# def index():
#     return "Hello, World!"
#
# # Add other routes...
#
# if __name__ == '__main__':
#     app.run(debug=True) # Use appropriate host/port for production