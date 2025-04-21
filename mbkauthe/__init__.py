# mbkauthe/__init__.py

import logging
from flask import Flask
# from flask_session import Session # No longer needed here
from flask_cors import CORS

# --- Initialize Extensions ---
# sess = Session() # No longer needed here

# --- Import Components ---
# Import only what's needed at module level or within functions
# config is loaded globally in config.py itself
# from .config import MBKAUTHE_CONFIG # Not strictly needed here

# --- Exports ---
# Define __all__ to explicitly state what the package exports
__all__ = [
    "validate_session",
    "check_role_permission",
    "validate_session_and_role",
    "authenticate_token",
    "get_user_data",
    "mbkauthe_bp",          # Export the blueprint
    "configure_mbkauthe",   # Export the setup function
    "db_pool",              # Export the pool if direct access is needed
    "get_cookie_options"    # Export utility if needed
]


# --- Setup Function ---
def configure_mbkauthe(app: Flask):
    """
    Configures mbkauthe components (config, DB pool, routes) for the Flask app.
    NOTE: This version DOES NOT initialize Flask-Session itself.
          The main application should set app.session_interface manually.

    Args:
        app (Flask): The Flask application instance.
    """
    # --- Import Components INSIDE the function ---
    # Import other components only when the function is called
    from .config import configure_flask_app, MBKAUTHE_CONFIG # Need config dict here
    from .db import init_db_pool, close_db_pool, db_pool # Need db_pool for teardown
    from .routes import mbkauthe_bp # Blueprint needed for registration

    logger = logging.getLogger(__name__)
    logger.info("Configuring mbkauthe base components for Flask app...")

    # 1. Apply mbkauthe specific configurations to the Flask app
    # This loads MBKAUTHE_CONFIG into app.config['MBKAUTHE_CONFIG']
    # and sets other Flask config keys (SECRET_KEY, SESSION_*, SQLALCHEMY_DATABASE_URI etc.)
    configure_flask_app(app)

    # 2. Initialize Database Pool
    try:
        init_db_pool()
    except Exception as e:
        logger.error(f"Failed to initialize database pool during configure_mbkauthe: {e}", exc_info=True)
        raise RuntimeError("Failed to initialize mbkauthe database pool") from e

    # 3. Initialize Flask-Session <-- SKIPPED -->
    # sess.init_app(app) # <--- REMOVED / COMMENTED OUT
    # logger.info(f"Flask-Session default init skipped (use custom interface).")

    # 4. Initialize CORS (Optional - can be done per-blueprint or globally)
    # Example: Allow CORS for the mbkauthe blueprint specifically
    # CORS(mbkauthe_bp, supports_credentials=True, origins=["*.yourdomain.com"]) # Adjust origins

    # 5. Register the Blueprint containing /mbkauthe/api/* routes
    app.register_blueprint(mbkauthe_bp)
    logger.info("mbkauthe API blueprint registered.")

    # 6. Register App Teardown for DB Pool Cleanup
    # Ensure db_pool is accessible in this scope if not imported globally
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        # Need access to the close_db_pool function
        close_db_pool()
        # logger.debug("Database pool closed on app context teardown.")

    logger.info("mbkauthe base configuration complete (session interface to be set by app).")

# --- Import items needed for export AFTER the function definition ---
# These are imported so they can be accessed via `from mbkauthe import ...`
from .middleware import (
    validate_session,
    check_role_permission,
    validate_session_and_role,
    authenticate_token,
    get_user_data,
)
from .routes import mbkauthe_bp # Ensure blueprint is available for export
from .db import db_pool # Export pool object if needed
from .utils import get_cookie_options # Export utils if needed
from mbkauthe.custom_session_interface import CustomDbSessionInterface