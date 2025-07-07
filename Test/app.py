# app.py (Main Testing Website)

import os
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from dotenv import load_dotenv
from mbkauthepy import configure_mbkauthe
from mbkauthepy import CustomDbSessionInterface

# Load environment variables from .env file FIRST
load_dotenv()

# --- Flask App Initialization ---
app = Flask(__name__, instance_relative_config=False)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a-different-secret-key-for-flask-flash')
if app.config['SECRET_KEY'] == 'a-different-secret-key-for-flask-flash':
     print("WARNING: Using default FLASK_SECRET_KEY. Set a proper secret in .env for production.")

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- MBKAUTHE Configuration ---

try:
    app.logger.info("Attempting to configure mbkauthe base components...")
    configure_mbkauthe(app)
except Exception as e:
    app.logger.error(f"FATAL: Failed to configure mbkauthe: {e}", exc_info=True)
    print(f"FATAL: Failed to configure mbkauthe: {e}")
    exit(1)


try:
    # Get the table name from the config mbkauthe loaded into app.config
    mbk_config = app.config.get("MBKAUTHE_CONFIG", {})
    # Use SESSION_SQLALCHEMY_TABLE key, default to 'session' if not found
    session_table_name = mbk_config.get("SESSION_SQLALCHEMY_TABLE", "session")

    app.session_interface = CustomDbSessionInterface(table=session_table_name)
    app.logger.info(f"Custom session interface initialized for table '{session_table_name}'.")
except Exception as e:
     app.logger.error(f"FATAL: Failed to initialize custom session interface: {e}", exc_info=True)
     print(f"FATAL: Failed to initialize custom session interface: {e}")
     exit(1)

# --- Routes for the Testing Website ---

@app.route('/')
def index():
    """Public documentation page."""
    is_logged_in = 'user' in session
    username = session.get('user', {}).get('username') if is_logged_in else None
    return render_template('index.html', is_logged_in=is_logged_in, username=username)



@app.route('/home')
def home():
    """Protected home page."""
    # Manual session check for this route
    if 'user' not in session:
        flash('You need to be logged in to access the home page.', 'warning')
        # Redirect to login, passing the current page as 'next'
        # Use request.url or request.full_path depending on desired behavior
        next_url = request.full_path if request.args else request.path
        return redirect(url_for('login', next=next_url))

    # If logged in, get username and render home page
    user_info = session.get('user', {})
    username = user_info.get('username', 'User')
    return render_template('home.html', username=username)


@app.errorhandler(500)
def handle_internal_server_error(error):
    """
    Catches unhandled exceptions and renders a custom 500 error page.
    This is the Flask equivalent of the Express error-handling middleware.
    """
    # 1. Log the full error stack for debugging purposes
    #    This is equivalent to `console.error(err.stack)`
    app.logger.error(f"An unhandled exception occurred on URL {request.url}")
    app.logger.error(traceback.format_exc())  # Logs the full stack trace

    # 2. Prepare the context for your template
    #    This matches the context from your Node.js example
    context = {
        'layout': False,
        'code': 500,
        'error': "Internal Server Error",
        'message': "An unexpected error occurred on the server.",
        # SECURITY NOTE: Only show detailed errors in debug mode.
        # In production, you should not expose internal error details to the user.
        'details': str(error.original_exception) if app.debug else "No details available.",
        'pagename': "Home",
        'page': '/dashboard'
    }

    # 3. Render the Handlebars error template
    try:
        # Assuming your templates are in a 'templates' folder at the root
        template_path = os.path.join(app.root_path, 'templates', 'Error', 'dError.handlebars')
        with open(template_path, 'r', encoding='utf-8') as f:
            source = f.read()

        template = compiler.compile(source)
        html_output = template(context)

        # 4. Return the rendered template and the 500 status code
        return html_output, 500

    except Exception as e:
        # This is a fallback in case your error template itself has an error
        app.logger.critical(f"FATAL: The error handler failed to render the error template: {e}")
        return "<h1>Internal Server Error</h1><p>Additionally, the error reporting page failed to render.</p>", 500


# --- Run the App ---
if __name__ == '__main__':
    # Use host='0.0.0.0' to make it accessible on your network
    # Set debug=False in production!
    app.logger.info("Starting Flask testing website server...")
    # Use threaded=False if DB pool issues persist with reloader, but should be okay now.
    app.run(host='0.0.0.0', port=5000, debug=True)