# mbkauthepy/__init__.py

import logging
from flask import Flask
# from flask_session import Session # Not needed if session init is removed/handled by app
from flask_cors import CORS

# --- Initialize Extensions ---
# sess = Session() # Not needed here if app sets interface manually

# --- Import Components ---
# Import only what's needed at module level or within functions

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
    # "db_pool",           # REMOVED - No global pool to export
    "get_cookie_options",   # Export utility if needed
    "CustomDbSessionInterface" # Export the custom session interface class
]


# --- Setup Function ---
def configure_mbkauthe(app: Flask):
    """
    Configures mbkauthe components (config, routes) for the Flask app.
    Initializes DB connection functions but DOES NOT manage a global pool
    and DOES NOT initialize Flask-Session itself.

    Args:
        app (Flask): The Flask application instance.
    """
    # --- Import Components INSIDE the function ---
    from .config import configure_flask_app # Need this to apply config to app
    # from .db import init_db_pool, close_db_pool # REMOVED Pool functions
    from .routes import mbkauthe_bp # Blueprint needed for registration

    logger = logging.getLogger(__name__)
    logger.info("Configuring mbkauthe base components for Flask app...")

    # 1. Apply mbkauthe specific configurations to the Flask app
    # This loads MBKAUTHE_CONFIG into app.config['MBKAUTHE_CONFIG']
    # and sets other Flask config keys
    configure_flask_app(app)

    # 2. Initialize Database Pool <-- REMOVED -->
    # No pool initialization needed here. Connections are request-scoped.
    # logger.info("DB Pool initialization skipped (using request-scoped connections).")

    # 3. Initialize Flask-Session <-- SKIPPED -->
    # The main application (app.py) should set app.session_interface manually.
    # sess.init_app(app) # REMOVED
    # logger.info(f"Flask-Session default init skipped (use custom interface or app setup).")

    # 4. Initialize CORS (Optional)
    # CORS(mbkauthe_bp, ...)

    # 5. Register the Blueprint containing /mbkauthe/api/* routes
    app.register_blueprint(mbkauthe_bp)
    logger.info("mbkauthe API blueprint registered.")

    # 6. Register App Teardown for DB Pool Cleanup <-- REMOVED -->
    # No global pool to close. Individual connections are closed in 'finally' blocks.
    # @app.teardown_appcontext
    # def shutdown_session(exception=None):
    #     close_db_pool()

    logger.info("mbkauthe base configuration complete.")

# --- Import items needed for export AFTER the function definition ---
from .middleware import (
    validate_session,
    check_role_permission,
    validate_session_and_role,
    authenticate_token,
    get_user_data,
)
from .routes import mbkauthe_bp # Ensure blueprint is available for export
# from .db import db_pool # REMOVED pool export
from .utils import get_cookie_options # Export utils if needed

# CORRECTED IMPORT: Use relative import for modules within the same package
from .custom_session_interface import CustomDbSessionInterface