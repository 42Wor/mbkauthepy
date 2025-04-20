# app.py (Main Testing Website)

import os
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from dotenv import load_dotenv

# --- MBKAUTHE Import ---
try:
    # Import configure_mbkauthe to set up DB pool, routes etc.
    from mbkauthe import configure_mbkauthe
    # Import the custom interface (make sure file path is correct)
    from custom_session_interface import CustomDbSessionInterface
except ImportError as e:
    print(f"ERROR: Cannot import mbkauthe or custom session interface. Details: {e}")
    print("Ensure mbkauthe is installed (-e ./mbkauthe) and custom_session_interface.py exists.")
    exit(1)
except Exception as e:
    print(f"ERROR: An unexpected error occurred during imports: {e}")
    exit(1)

# Load environment variables from .env file FIRST
load_dotenv()

# --- Flask App Initialization ---
app = Flask(__name__, instance_relative_config=False)
# Set a secret key for Flask itself (needed for flash messages, separate from session secret)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a-different-secret-key-for-flask-flash')
if app.config['SECRET_KEY'] == 'a-different-secret-key-for-flask-flash':
     print("WARNING: Using default FLASK_SECRET_KEY. Set a proper secret in .env for production.")

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- MBKAUTHE Configuration ---
# Call configure_mbkauthe to set up DB pool, load mbkauthe config, register API routes.
# This version of configure_mbkauthe WILL NOT initialize Flask-Session.
try:
    app.logger.info("Attempting to configure mbkauthe base components...")
    configure_mbkauthe(app)
    # configure_mbkauthe logs its own success/failure messages now
except Exception as e:
    app.logger.error(f"FATAL: Failed to configure mbkauthe: {e}", exc_info=True)
    print(f"FATAL: Failed to configure mbkauthe: {e}")
    exit(1)

# --- Custom Session Interface Setup ---
# Explicitly set the session interface *after* basic app/mbkauthe config
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

@app.route('/login', methods=['GET']) # Only GET needed, POST is API
def login():
    """Login page - shows form."""
    if 'user' in session:
        return redirect(url_for('home'))
    # The actual login POST is handled by JavaScript calling the /mbkauthe/api/login endpoint.
    return render_template('login.html')

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

# --- Run the App ---
if __name__ == '__main__':
    # Use host='0.0.0.0' to make it accessible on your network
    # Set debug=False in production!
    app.logger.info("Starting Flask testing website server...")
    # Use threaded=False if DB pool issues persist with reloader, but should be okay now.
    app.run(host='0.0.0.0', port=5000, debug=True)