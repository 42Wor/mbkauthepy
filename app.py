# app.py (Main Testing Website)

import os
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from dotenv import load_dotenv

# --- MBKAUTHE Import ---
# Ensure mbkauthe is installed (e.g., pip install -e ./mbkauthe) or accessible
try:
    # We only need configure_mbkauthe here.
    # Session validation will be done manually in routes for this example.
    # API endpoints (/mbkauthe/api/*) are registered by configure_mbkauthe.
    from mbkauthe import configure_mbkauthe
except ImportError as e:
    print(f"ERROR: Cannot import mbkauthe. Make sure it's installed or accessible. Details: {e}")
    print("Try activating your virtual environment and running: pip install -e ./mbkauthe")
    exit(1)
except Exception as e:
    print(f"ERROR: An unexpected error occurred during mbkauthe import: {e}")
    exit(1)

# Load environment variables from .env file FIRST
load_dotenv()

# --- Flask App Initialization ---
# Use instance_relative_config=True if your config is complex or outside project root
app = Flask(__name__, instance_relative_config=False)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-flask-secret-key-for-flash') # Needed for flash messages

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- MBKAUTHE Configuration ---
# This sets up sessions, registers /mbkauthe/api/* routes, etc.
try:
    app.logger.info("Attempting to configure mbkauthe...")
    configure_mbkauthe(app)
    # configure_mbkauthe logs its own success/failure messages now
except Exception as e:
    app.logger.error(f"FATAL: Failed to configure mbkauthe: {e}", exc_info=True)
    print(f"FATAL: Failed to configure mbkauthe: {e}")
    exit(1)

# --- Routes for the Testing Website ---

@app.route('/')
def index():
    """Public documentation page."""
    # Renders templates/index.html
    # Pass login status to template for conditional rendering
    is_logged_in = 'user' in session
    username = session.get('user', {}).get('username') if is_logged_in else None
    return render_template('index.html', is_logged_in=is_logged_in, username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - shows form (GET) or handles login via JS (POST handled by mbkauthe API)."""
    if 'user' in session:
        # If user is already logged in, redirect to home
        return redirect(url_for('home'))

    # For GET request, just render the login form template.
    # The actual login POST is handled by JavaScript calling the /mbkauthe/api/login endpoint.
    return render_template('login.html')

@app.route('/home')
def home():
    """Protected home page."""
    # Manual session check for this route
    if 'user' not in session:
        flash('You need to be logged in to access the home page.', 'warning')
        # Redirect to login, passing the current page as 'next'
        return redirect(url_for('login', next=request.url))

    # If logged in, get username and render home page
    user_info = session.get('user', {})
    username = user_info.get('username', 'User')
    return render_template('home.html', username=username)

# Note: Logout is handled entirely by JavaScript calling the /mbkauthe/api/logout endpoint.
# We don't strictly need a separate Flask route for it unless we want a confirmation page.

# --- Run the App ---
if __name__ == '__main__':
    # Use host='0.0.0.0' to make it accessible on your network
    # Set debug=False in production!
    app.logger.info("Starting Flask testing website server...")
    # Ensure debug=True to see detailed errors during testing
    # Use threaded=False if you encounter issues with DB pool and reloader,
    # though the robust pool handling should mitigate this.
    app.run(host='0.0.0.0', port=5000, debug=True)