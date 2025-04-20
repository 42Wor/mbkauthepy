      
# mbkauthepy (Python/Flask Version)

<!-- Add relevant badges for Python later, e.g., PyPI version, build status -->
<!-- [![Build Status](YOUR_CI_BADGE_URL)](YOUR_CI_LINK) -->
[![CodeQL](https://github.com/42Wor/YOUR_REPO_NAME/actions/workflows/codeql.yml/badge.svg)](https://github.com/42Wor/YOUR_REPO_NAME/actions/workflows/codeql.yml)

## Table of Contents

- [mbkauthe (Python/Flask Version)](#mbkauthe-pythonflask-version)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Basic Setup](#basic-setup)
    - [Environment Configuration (`.env`)](#environment-configuration-env)
  - [Middleware & Helper Function Documentation](#middleware--helper-function-documentation)
    - [`@validate_session`](#validate_session)
    - [`@check_role_permission(required_role)`](#check_role_permissionrequired_role)
    - [`@validate_session_and_role(required_role)`](#validate_session_and_rolerequired_role)
    - [`get_user_data(username, parameters)`](#get_user_datausername-parameters)
    - [`@authenticate_token`](#authenticate_token)
  - [API Endpoints](#api-endpoints)
    - [Login](#login)
    - [Logout](#logout)
    - [Terminate All Sessions](#terminate-all-sessions)
    - [Package Information](#package-information)
    - [Version Information](#version-information)
    - [Package Dependency Information](#package-dependency-information)
  - [Database Structure](#database-structure)
    - [Important Note on Passwords](#important-note-on-passwords)
  - [License](#license)
  - [Contact & Support](#contact--support)

`mbkauthe` is a reusable authentication system for **Python Flask applications**, designed to simplify session management, user authentication, and role-based access control. It integrates seamlessly with PostgreSQL and supports features like Two-Factor Authentication (2FA), session restoration, and reCAPTCHA verification. This is a port and adaptation of the original Node.js `mbkauthe` library.

## Features

-   **Session Management**: Secure server-side session handling using `Flask-Session` with configurable backends (PostgreSQL via SQLAlchemy, Filesystem, Redis, etc.).
-   **Role-Based Access Control**: Decorators to easily validate user roles and permissions for specific routes.
-   **Two-Factor Authentication (2FA)**: Optional TOTP-based 2FA support (using `pyotp`) for enhanced security during login.
-   **reCAPTCHA Integration**: Protect login endpoints with Google reCAPTCHA v2 verification.
-   **Cookie Management**: Configurable session cookie expiration, domain, security flags, and SameSite settings via Flask-Session.
-   **PostgreSQL Integration**: Uses a `psycopg2` connection pool for efficient database interactions (Users, 2FA data). Session data can also be stored in PostgreSQL via the `sqlalchemy` session type.
-   **Configuration Driven**: Behavior controlled via environment variables loaded from a `.env` file.

## Installation

It's highly recommended to use a virtual environment for your project.

1.  **Activate your virtual environment:**
    ```bash
    # Example for Linux/macOS/WSL
    source venv/bin/activate
    # Example for Windows
    # .\venv\Scripts\activate
    ```

2.  **Install the package:**
    *   If published on PyPI:
        ```bash
        pip install mbkauthe
        ```
    *   For local development (installing from the source directory containing `pyproject.toml`):
        ```bash
        pip install -e .
        # Or if mbkauthe is a subdirectory: pip install -e ./mbkauthe
        ```

3.  **Install required dependencies** used by `mbkauthe` (ensure these are in your project's `requirements.txt` or installed manually):
    ```bash
    pip install Flask Flask-Session psycopg2-binary python-dotenv bcrypt pyotp requests Flask-Cors SQLAlchemy # Add others as needed
    ```

## Usage

### Basic Setup

1.  **Import and configure `mbkauthe` in your Flask application factory or main `app.py`:**

    ```python
    # app.py
    import os
    from flask import Flask, render_template, session # etc.
    from dotenv import load_dotenv

    # Import the configuration function from the mbkauthe package
    try:
        from mbkauthe import configure_mbkauthe
        # Import decorators/functions if needed directly in app.py
        # from mbkauthe import validate_session, check_role_permission # etc.
    except ImportError:
        print("ERROR: Cannot import mbkauthe. Ensure it's installed.")
        exit()

    # Load .env file BEFORE configuring mbkauthe
    load_dotenv()

    app = Flask(__name__)
    # Set a secret key for Flask itself (for flash messages etc.)
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default-flask-secret')

    # Configure mbkauthe (sets up DB pool, session, registers API routes)
    try:
        configure_mbkauthe(app)
    except Exception as e:
        print(f"FATAL: Failed to configure mbkauthe: {e}")
        exit()

    # --- Your Application Routes ---
    @app.route('/')
    def index():
        return "Welcome!"

    @app.route('/protected')
    @validate_session # Example using mbkauthe decorator
    def protected_route():
        username = session['user']['username']
        return f"Hello, {username}! This is a protected area."

    # --- Run the App ---
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000, debug=True) # Set debug=False for production
    ```

2.  **Ensure your `.env` file is properly configured.**

### Environment Configuration (`.env`)

Create a `.env` file in your project root. The `mbkauthe` library expects configuration within a JSON string assigned to the `mbkautheVar` environment variable.

**Example `.env` file:**

```dotenv
# Secret key for Flask flash messages, CSRF protection etc. (separate from session key)
FLASK_SECRET_KEY='a-very-strong-random-secret-key-for-flask-itself'

# Configuration for the mbkauthe library
mbkautheVar='{
    "APP_NAME": "YourAppName",
    "RECAPTCHA_SECRET_KEY": "your-google-recaptcha-secret-key",
    "RECAPTCHA_Enabled": "false",
    "BypassUsers": ["admin_user", "test_user"],
    "SESSION_SECRET_KEY": "generate-a-very-long-random-unpredictable-secret-here",
    "IS_DEPLOYED": "false",
    "LOGIN_DB": "postgresql://db_user:db_password@db_host:db_port/auth_database",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": "7",
    "DOMAIN": "localhost",
    "Main_SECRET_TOKEN": "generate-another-strong-secret-for-api-auth",
    "SESSION_TYPE": "filesystem",
    "SESSION_SQLALCHEMY_TABLE": "session",
    "SESSION_SQLALCHEMY": null,
    "EncryptedPassword": "false"
}'

# Notes:
# - Replace placeholder values with your actual secrets and settings.
# - APP_NAME: Users must have this in their AllowedApps unless they are SuperAdmin.
# - SESSION_SECRET_KEY: Used by Flask-Session to sign the session cookie. Make it strong!
# - IS_DEPLOYED: Set to "true" in production. Affects cookie 'secure' flag.
# - LOGIN_DB: Your PostgreSQL connection string. Use postgresql:// scheme.
# - COOKIE_EXPIRE_TIME: Session duration in days.
# - DOMAIN: Set to your actual domain (e.g., "example.com") if IS_DEPLOYED is "true" for cross-subdomain cookies. Use "localhost" for local development.
# - Main_SECRET_TOKEN: Used to authenticate the /terminateAllSessions endpoint.
# - SESSION_TYPE: Where to store sessions ('filesystem', 'sqlalchemy', 'redis', 'memcached').
#   - If 'filesystem', create a 'flask_session' directory.
#   - If 'sqlalchemy', ensure the table name matches SESSION_SQLALCHEMY_TABLE and the schema is correct (see Database Structure).
# - SESSION_SQLALCHEMY_TABLE: Name of the DB table for sessions if SESSION_TYPE is 'sqlalchemy'.
# - EncryptedPassword: Set to "true" if passwords in the DB are bcrypt hashes, "false" if plaintext.

    

IGNORE_WHEN_COPYING_START
Use code with caution. Markdown
IGNORE_WHEN_COPYING_END
Middleware & Helper Function Documentation

These functions/decorators are provided by the mbkauthe package. Import them as needed (e.g., from mbkauthe import validate_session).
@validate_session

A Flask decorator to validate the user's session before allowing access to a route. It checks if a user is logged in via the Flask session object, verifies the session against the database (Users table SessionId), checks if the user is active, and confirms application access (AllowedApps). If validation fails, it typically renders an appropriate error template (Not Logged In, Session Expired, Account Inactive, Not Authorized for App).

    Usage: Apply as a decorator to your Flask route functions.

          
    from flask import session
    from mbkauthe import validate_session

    @app.route('/dashboard')
    @validate_session
    def dashboard():
        # Code here only runs if session is valid
        user_id = session['user']['id']
        return f"Welcome to your dashboard, user {user_id}!"

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Python
    IGNORE_WHEN_COPYING_END

@check_role_permission(required_role)

A Flask decorator factory used to check if the logged-in user (whose session must already be validated, typically by using @validate_session first) has the specified role.

    Parameters:

        required_role (str): The role name required to access the route (e.g., 'SuperAdmin', 'NormalUser'). Case-sensitive, must match roles in the database. Can also be 'Any' or 'any' to allow any authenticated user.

    Usage: Apply after @validate_session.

          
    from mbkauthe import validate_session, check_role_permission

    @app.route('/admin/users')
    @validate_session
    @check_role_permission('SuperAdmin')
    def manage_users():
        # Only SuperAdmins with valid sessions can reach here
        return "User Management Panel"

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Python
    IGNORE_WHEN_COPYING_END

@validate_session_and_role(required_role)

A convenience Flask decorator factory that combines the functionality of @validate_session and @check_role_permission. It first validates the session and then checks the required role.

    Parameters:

        required_role (str): The role name required (e.g., 'SuperAdmin'). Use 'Any' or 'any' to only require a valid session without a specific role check.

    Usage: Apply as a single decorator instead of the two separate ones.

          
    from mbkauthe import validate_session_and_role

    @app.route('/admin/settings')
    @validate_session_and_role('SuperAdmin')
    def admin_settings():
        # Only SuperAdmins with valid sessions can reach here
        return "Admin Settings"

    @app.route('/my-profile')
    @validate_session_and_role('Any') # Requires login, but any role is fine
    def my_profile():
        return "Your Profile Page"

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Python
    IGNORE_WHEN_COPYING_END

get_user_data(username, parameters)

A function to retrieve specific user data fields from the Users and profiledata tables.

    Parameters:

        username (str): The UserName of the user whose data is needed.

        parameters (list or str):

            A list of strings specifying the exact field names required from the Users or profiledata tables (e.g., ['UserName', 'Role', 'FullName', 'email']).

            The string "profiledata" to retrieve all non-sensitive Users fields and all profiledata fields.

            Note: The Password field is excluded by default unless explicitly requested in the list.

    Returns:

        dict: A dictionary containing the requested user data fields.

        dict: An error dictionary (e.g., {'error': 'User not found'}) if the user or data doesn't exist or an error occurs.

    Usage:

          
    from mbkauthe import get_user_data

    # Get specific fields
    user_info = get_user_data('some_user', ['Role', 'Active', 'FullName'])
    if 'error' not in user_info:
        print(f"Role: {user_info.get('Role')}")
        print(f"Full Name: {user_info.get('FullName')}")

    # Get profile data
    profile = get_user_data('another_user', 'profiledata')

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Python
    IGNORE_WHEN_COPYING_END

@authenticate_token

A Flask decorator used to protect specific API endpoints that require authentication via a static token sent in the Authorization header, rather than a user session cookie. It compares the provided header value against the Main_SECRET_TOKEN configured in the .env file.

    Usage: Apply to API routes that need machine-to-machine or administrative authentication without user login.

          
    from mbkauthe import authenticate_token

    @app.route('/api/internal/do-something', methods=['POST'])
    @authenticate_token
    def internal_api():
        # Only requests with the correct Authorization header token reach here
        return jsonify({"status": "success", "message": "Internal action performed"})

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Python
    IGNORE_WHEN_COPYING_END

API Endpoints

These endpoints are registered automatically when you call configure_mbkauthe(app).
Login

POST /mbkauthe/api/login

    Authenticates a user based on username and password (and optionally 2FA token and reCAPTCHA). Creates a server-side session and sets the session cookie.

    Request Body (JSON):

        username (str): User's username.

        password (str): User's plaintext password.

        token (str, optional): 2FA token if enabled for the user.

        recaptcha (str, optional): Google reCAPTCHA response token if enabled.

    Response:

        200 OK: Login successful. Body: {"success": true, "message": "Login successful", "sessionId": "..."}

        400 Bad Request: Missing fields, invalid input, failed reCAPTCHA. Body: {"success": false, "message": "Reason..."}

        401 Unauthorized: Incorrect username/password, invalid 2FA token. Body: {"success": false, "message": "Reason...", "errorCode": 603} (or other codes).

        403 Forbidden: Account inactive, user not authorized for the configured APP_NAME. Body: {"success": false, "message": "Reason..."}

        500 Internal Server Error: Database error, configuration issue. Body: {"success": false, "message": "Internal Server Error"}

Logout

POST /mbkauthe/api/logout

    Logs out the current user by clearing their session data on the server and instructing the browser to delete the session cookie. Requires a valid session cookie to be sent with the request.

    Response:

        200 OK: Logout successful. Body: {"success": true, "message": "Logout successful"}

        400 Bad Request: User was not logged in (no valid session cookie). Body: {"success": false, "message": "Not logged in"}

        500 Internal Server Error: Database error during session clearing. Body: {"success": false, "message": "Internal Server Error during logout"}

Terminate All Sessions

POST /mbkauthe/api/terminateAllSessions

    Authentication: Requires a valid Main_SECRET_TOKEN (from .env) sent in the Authorization header (e.g., Authorization: YOUR_SECRET_TOKEN_VALUE).

    Invalidates all user sessions by clearing the SessionId in the Users table and potentially clearing the server-side session store (e.g., truncating the session table if using SQLAlchemy). Use with caution!

    Response:

        200 OK: All sessions terminated successfully. Body: {"success": true, "message": "All sessions terminated successfully"}

        401 Unauthorized: Missing or incorrect Authorization header token.

        500 Internal Server Error: Database error during termination. Body: {"success": false, "message": "Internal Server Error during session termination"}

Package Information

GET /mbkauthe/package

    Description: Retrieves metadata about the installed mbkauthe Python package using importlib.metadata.

    Response:

        200 OK: Successfully retrieved package metadata.

            Body: JSON object containing package metadata (name, version, author, etc.).

        404 Not Found: Package mbkauthe not found in the environment.

        500 Internal Server Error.

Version Information

GET /mbkauthe/version or /mbkauthe/v

    Description: Retrieves the current version of the installed mbkauthe Python package.

    Response:

        200 OK: Successfully retrieved the version information.

            Body: JSON object containing the version, e.g., { "version": "0.1.0" }.

        404 Not Found: Package mbkauthe not found.

        500 Internal Server Error.

Package Dependency Information

GET /mbkauthe/package-lock

    Description: Attempts to retrieve dependency information for mbkauthe. Primarily returns the library's own direct dependencies as listed in its package metadata. It may attempt to find and parse project lock files (poetry.lock, Pipfile.lock) but this is less standard/reliable in Python compared to Node.js's package-lock.json.

    Response:

        200 OK: Successfully retrieved dependency information.

            Body: JSON object containing dependency details.

        404 Not Found: Package mbkauthe not found.

        501 Not Implemented: Could not find or parse a project lock file (if that method was attempted).

        500 Internal Server Error.

Database Structure

This library interacts with up to four primary PostgreSQL tables:

    Users: Stores core user authentication and authorization data.

    session: Stores server-side session data (used if SESSION_TYPE is sqlalchemy or if using a custom DB interface). Schema depends on the session interface used.

    TwoFA: Stores Two-Factor Authentication (2FA) secrets and status for users.

    profiledata: Stores additional user profile information (queried by get_user_data).

For detailed information about recommended table columns, schemas, and example queries, refer to the Database Guide (docs/db.md). (Ensure this file exists and is updated for Python)
Important Note on Passwords

The mbkauthe package can handle either plaintext passwords or bcrypt hashed passwords stored in the Users.Password column.

    Configuration: This behavior is controlled by the "EncryptedPassword" setting in your .env file's mbkautheVar.

        Set "EncryptedPassword": "false" if you store plaintext passwords. (Less Secure)

        Set "EncryptedPassword": "true" if you store bcrypt hashes. (Recommended)

    Consistency: Ensure your configuration matches how passwords are actually stored in your database. Mismatches will cause login errors.

    Generating Hashes: If using "EncryptedPassword": "true", you must generate valid bcrypt hashes before inserting them into the database.

License

This project is licensed under the Mozilla Public License 2.0. See the LICENSE file for details.
Contact & Support

For questions or contributions related to this Python adaptation, please contact Maaz Waheed via his GitHub profile or associated contact methods.

Developed by Maaz Waheed