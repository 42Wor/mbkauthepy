# mbkauthepy/__init__.py

import logging
from flask import Flask, render_template, url_for
from werkzeug.exceptions import HTTPException
from flask_cors import CORS

# --- Exports ---
__all__ = [
    "validate_session",
    "check_role_permission",
    "validate_session_and_role",
    "authenticate_token",
    "authapi",  # Added new authapi middleware
    "get_user_data",
    "mbkauthe_bp",
    "configure_mbkauthe",
    "get_cookie_options"
]


# --- Setup Function ---
def configure_mbkauthe(app: Flask):
    """
    Configures mbkauthe components (config, routes, error handler) for the Flask app.

    Args:
        app (Flask): The Flask application instance.
    """
    from .config import configure_flask_app
    from .routes import mbkauthe_bp

    logger = logging.getLogger(__name__)
    logger.info("Configuring mbkauthe base components for Flask app...")

    configure_flask_app(app)
    app.register_blueprint(mbkauthe_bp)
    logger.info("mbkauthe API blueprint registered.")

# --- Import items needed for export AFTER the function definition ---
from .middleware import (
    validate_session,
    check_role_permission,
    validate_session_and_role,
    authenticate_token,
    authapi  # Import the new authapi middleware
)
from .routes import mbkauthe_bp
from .utils import get_cookie_options, get_user_data