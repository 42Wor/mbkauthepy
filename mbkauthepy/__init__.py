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

    # Register the Global Error Handler
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        """
        Catches all HTTP exceptions and renders our single error page.
        """
        # ==================================================================
        #  FIXED SECTION
        # ==================================================================
        # Check if the 'home' endpoint is registered before trying to build a URL for it.
        # The correct way is to check the app's view_functions dictionary.
        if 'home' in app.view_functions:
            home_url = url_for('home')
        else:
            # Fallback to the root URL if no 'home' endpoint exists.
            home_url = '/'
        # ==================================================================

        response = error.get_response()
        response.data = render_template(
            "error.html",
            code=error.code,
            name=error.name,
            message=error.description,
            page_url=home_url,  # Use the safely determined URL
            page_name="home"
        )
        response.content_type = "text/html"
        return response

    logger.info("Global HTTP error handler registered.")
    logger.info("mbkauthe base configuration complete.")


# --- Import items needed for export AFTER the function definition ---
from .middleware import (
    validate_session,
    check_role_permission,
    validate_session_and_role,
    authenticate_token,

)
from .routes import mbkauthe_bp
from .utils import get_cookie_options