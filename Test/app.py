# app.py (Main Testing Website)

import os
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from dotenv import load_dotenv
from mbkauthepy import (configure_mbkauthe ,
                        validate_session,
                        check_role_permission,
                        authenticate_token
                        )

# Load environment variables from .env file FIRST
load_dotenv()

# --- Flask App Initialization ---
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- MBKAUTHE Configuration ---

configure_mbkauthe(app)




# --- Routes for the Testing Website ---

@app.route('/')
def index():
    """Public documentation page."""
    is_logged_in = 'user' in session
    username = session.get('user', {}).get('username') if is_logged_in else None
    return render_template('index.html', is_logged_in=is_logged_in, username=username)



@app.route('/home')
@validate_session
def home():
    """Protected home page."""
    # Manual session check for this route
    if 'user' not in session:
        flash('You need to be logged in to access the home page.', 'warning')
        # Redirect to login, passing the current page as 'next'
        # Use request.url or request.full_path depending on desired behavior
        next_url = request.full_path if request.args else request.path
        return redirect(url_for('mbkauthe.login_page', next=next_url))

    # If logged in, get username and render home page
    user_info = session.get('user', {})
    username = user_info.get('username', 'User')
    return render_template('home.html', username=username)


@app.route('/protected')
@validate_session
def protected_route():
    return "<h1>Success!</h1><p>You have accessed a protected page because you have a valid session.</p>"


@app.route('/admin-only')
@validate_session  # Good practice to validate session first
@check_role_permission('Admin')
def admin_only_route():
    return "<h1>Success!</h1><p>You have accessed this page because you are an Admin.</p>"


if __name__ == '__main__':
    # Use host='0.0.0.0' to make it accessible on your network
    # Set debug=False in production!
    app.logger.info("Starting Flask testing website server...")
    # Use threaded=False if DB pool issues persist with reloader, but should be okay now.
    app.run(host='0.0.0.0', port=5000, debug=True)