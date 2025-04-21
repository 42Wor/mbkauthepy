# mbkauthe (Python/Flask Version)

<!-- Add relevant badges here if applicable (e.g., PyPI version, build status) -->
<!-- [![PyPI version](https://badge.fury.io/py/mbkauthe.svg)](https://badge.fury.io/py/mbkauthe) -->
<!-- [![Build Status](...)](...) -->

## Table of Contents

- [mbkauthe (Python/Flask Version)](#mbkauthe-pythonflask-version)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Implementation in a Project](#implementation-in-a-project)
    - [Basic Setup](#basic-setup)
    - [Environment Variables (`.env`)](#environment-variables-env)
  - [Middleware & Function Documentation](#middleware--function-documentation)
    - [`@validate_session`](#validatesession)
    *   [`@check_role_permission(required_role)`](#check_role_permissionrequired_role)
    *   [`@validate_session_and_role(required_role)`](#validatesessionandrolerequired_role)
    *   [`get_user_data(username, parameters)`](#get_user_datausername-parameters)
    *   [`@authenticate_token`](#authenticate_token)
  - [API Endpoints](#api-endpoints)
    - [Login](#login)
    - [Logout](#logout)
    - [Terminate All Sessions](#terminate-all-sessions)
    - [Package Information](#package-information)
    - [Version Information](#version-information)
    - [Package Lock Information](#package-lock-information)
  - [Database Structure](#database-structure)
    - [Users Table](#users-table)
    - [Session Table](#session-table)
    - [Two-Factor Authentication (TwoFA) Table](#two-factor-authentication-twofa-table)
    - [Profile Data Table](#profile-data-table)
    - [Query to Add a User](#query-to-add-a-user)
    - [Important Note on Passwords](#important-note-on-passwords)
  - [License](#license)
  - [Contact & Support](#contact--support)

`mbkauthe` is a reusable authentication system for Python Flask applications, ported from the original Node.js version. It simplifies session management, user authentication, role-based access control, and database interaction. It integrates with PostgreSQL and supports features like optional Two-Factor Authentication (2FA) and reCAPTCHA verification.

## Features

-   **Session Management**: Secure server-side session handling using `Flask-Session` with configurable backends (Database via SQLAlchemy, Filesystem, Redis, etc.).
-   **Role-Based Access Control**: Decorators to easily validate user roles and permissions for specific routes.
-   **Two-Factor Authentication (2FA)**: Optional TOTP-based 2FA support for enhanced security (requires `pyotp`).
-   **reCAPTCHA Integration**: Protect login endpoints with Google reCAPTCHA (requires `requests`).
-   **Cookie Management**: Configurable session cookie expiration, domain, security flags, etc.
*   **PostgreSQL Integration**: Uses a connection pool (`psycopg2`) for efficient database interactions.
*   **Password Handling**: Supports both plaintext and bcrypt-hashed passwords (configurable).

## Installation

1.  **Prerequisites:** Python 3.8+, pip.
2.  **Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # .\venv\Scripts\activate  # Windows
    ```
3.  **Install Dependencies:** Ensure you have a `requirements.txt` or `pyproject.toml` listing all needed packages (Flask, Flask-Session, psycopg2-binary, python-dotenv, bcrypt, requests, pyotp, Flask-Cors, SQLAlchemy, etc.) and install them:
    ```bash
    pip install -r requirements.txt
    # or install manually:
    # pip install Flask Flask-Session psycopg2-binary python-dotenv bcrypt requests pyotp Flask-Cors SQLAlchemy importlib-metadata Pillow Werkzeug toml
    ```
4.  **Install mbkauthe:** If `mbkauthe` is a local package within your project:
    ```bash
    # Make sure mbkauthe folder has __init__.py and pyproject.toml
    pip install -e ./mbkauthe
    ```
    If it were published to PyPI:
    ```bash
    # pip install mbkauthe
    ```

## Usage

### Implementation in a Project

This repository itself, particularly the `app.py` and `templates/` folder provided in the testing website example, serves as a demonstration of how to integrate and use the `mbkauthe` package within a Flask application. It shows:

*   Initializing the library.
*   Creating public and protected routes.
*   Building a login page that interacts with the library's API.
*   Handling logout.

### Basic Setup

1.  **Import and configure `mbkauthe` in your main Flask app file (e.g., `app.py`):**

    ```python
    import os
    from flask import Flask, render_template # etc.
    from dotenv import load_dotenv

    # Import the configuration function from mbkauthe
    try:
        from mbkauthe import configure_mbkauthe
        # Import decorators/functions if needed directly in app.py routes
        # from mbkauthe import validate_session, check_role_permission # etc.
    except ImportError:
        print("ERROR: Cannot import mbkauthe. Ensure it's installed.")
        exit()

    # Load .env file BEFORE initializing app or mbkauthe
    load_dotenv()

    # Create Flask app instance
    app = Flask(__name__)
    # Set a Flask secret key (for flash messages, etc.)
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default-flask-secret')

    # Configure mbkauthe (loads its config, sets up DB pool, session, registers API routes)
    try:
        configure_mbkauthe(app)
    except Exception as e:
        print(f"FATAL: Failed to configure mbkauthe: {e}")
        exit()

    # --- Your Application Routes ---
    @app.route('/')
    def index():
        return render_template('index.html') # Example public route

    # Example protected route using a decorator from mbkauthe
    from mbkauthe import validate_session # Import decorator

    @app.route('/protected')
    @validate_session # Apply the decorator
    def protected_route():
        # This code only runs if the user has a valid session
        user_info = session.get('user', {})
        return f"Welcome to the protected area, {user_info.get('username')}!"

    # --- Run the App ---
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000, debug=True) # Set debug=False for production
    ```

2.  **Ensure your `.env` file is properly configured.**

### Environment Variables (`.env`)

Create a `.env` file in your project root. It must contain a variable `mbkautheVar` holding a JSON string with the necessary configuration keys.

```dotenv
# Example .env file

# Optional: Secret key for Flask flash messages etc.
# FLASK_SECRET_KEY=a-separate-strong-secret-for-flask

# mbkauthe configuration as a JSON string
mbkautheVar='{
    "APP_NAME": "YourAppName",
    "RECAPTCHA_SECRET_KEY": "your-google-recaptcha-v2-secret-key",
    "RECAPTCHA_Enabled": "false",
    "BypassUsers": ["admin_user", "test_user"],
    "SESSION_SECRET_KEY": "a-very-long-random-unpredictable-secret-for-sessions",
    "IS_DEPLOYED": "false",
    "LOGIN_DB": "postgresql://db_user:db_password@db_host:db_port/db_name",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": "7",
    "DOMAIN": "localhost",
    "Main_SECRET_TOKEN": "another-strong-secret-for-internal-api-auth",
    "SESSION_TYPE": "sqlalchemy",
    "SESSION_SQLALCHEMY_TABLE": "session",
    "SESSION_SQLALCHEMY": null,
    "EncryptedPassword": "false"
}'

# Add other environment variables for your app if needed (e.g., GitHub tokens)
# GITHUB_TOKEN=...
# GITHUB_OWNER=...


**Key `mbkautheVar` Settings:**

*   `APP_NAME`: Identifier for your application. Used for authorization checks (`AllowedApps` in DB).
*   `RECAPTCHA_Enabled`: `"true"` or `"false"`. If true, `RECAPTCHA_SECRET_KEY` is required.
*   `BypassUsers`: JSON array of usernames exempt from reCAPTCHA.
*   `SESSION_SECRET_KEY`: **Crucial.** Long, random secret for signing session cookies.
*   `IS_DEPLOYED`: `"true"` or `"false"`. Affects cookie security flags (`Secure`, `Domain`).
*   `LOGIN_DB`: PostgreSQL connection string (must start with `postgresql://`).
*   `MBKAUTH_TWO_FA_ENABLE`: `"true"` or `"false"`. Enables/disables 2FA checks.
*   `COOKIE_EXPIRE_TIME`: Session duration in days.
*   `DOMAIN`: Domain for cookies (e.g., `"yourdomain.com"`). Set to `"localhost"` if `IS_DEPLOYED` is false. Prepend `.` for subdomains (e.g., `".yourdomain.com"`) if needed.
*   `Main_SECRET_TOKEN`: Secret token used by `@authenticate_token` decorator for protecting specific API endpoints (like `/terminateAllSessions`).
*   `SESSION_TYPE`: Backend for Flask-Session (`"sqlalchemy"`, `"filesystem"`, `"redis"`, etc.).
*   `SESSION_SQLALCHEMY_TABLE`: Table name if `SESSION_TYPE` is `"sqlalchemy"`.
*   `EncryptedPassword`: `"true"` if passwords in DB are bcrypt hashes, `"false"` if plaintext. **See DB section note.**

## Middleware & Function Documentation

These decorators and functions are provided by the `mbkauthe` package (import them like `from mbkauthe import validate_session`).

### `@validate_session`

Decorator to protect Flask routes. Ensures the user has an active, valid session according to the database (`Users` table `SessionId` and `Active` status) and has access to the current `APP_NAME` (via `AllowedApps` unless `Role` is `SuperAdmin`).

*   If validation fails, it typically renders an appropriate error template (Not Logged In, Session Expired, Account Inactive, Not Authorized for App).
*   It automatically attempts to restore a session from the `sessionId` cookie if the Flask session is missing but the cookie exists.

**Usage:**

```python
from flask import session
from mbkauthe import validate_session

@app.route('/dashboard')
@validate_session # Apply decorator
def dashboard():
    # Code here only runs for valid, logged-in users authorized for this app
    user_info = session.get('user')
    return f"Welcome to your dashboard, {user_info['username']}!"
```

---

### `@check_role_permission(required_role)`

Decorator factory to check if the logged-in user (whose session must *already* be validated, e.g., by using `@validate_session` first) has the specified role.

*   **Parameters:**
    *   `required_role` (str): The exact role string required (e.g., `"SuperAdmin"`, `"NormalUser"`). Case-sensitive. Can also be `"Any"` or `"any"` to allow any authenticated user.
*   If the user's role (from `session['user']['role']`) doesn't match, it renders an "Access Denied" error template.

**Usage:**

```python
from mbkauthe import validate_session, check_role_permission

@app.route('/admin/users')
@validate_session # First, ensure valid session
@check_role_permission("SuperAdmin") # Then, check for specific role
def admin_user_management():
    # Only SuperAdmins with valid sessions can reach here
    return "User Management Panel"

@app.route('/any_logged_in_feature')
@validate_session
@check_role_permission("Any") # Or "any"
def feature_for_all_users():
    # Any user with a valid session can reach here
    return "This feature is available to all logged-in users."
```

---

### `@validate_session_and_role(required_role)`

A convenience decorator factory that combines `@validate_session` and `@check_role_permission`. It first validates the session and then checks the role.

*   **Parameters:**
    *   `required_role` (str): The role required (e.g., `"SuperAdmin"`, `"Any"`).
*   Handles all error conditions from both underlying decorators.

**Usage:**

```python
from mbkauthe import validate_session_and_role

@app.route('/super_admin_only')
@validate_session_and_role("SuperAdmin")
def super_admin_feature():
    # Only SuperAdmins with valid sessions can reach here
    return "Super Admin Feature"
```

---

### `get_user_data(username, parameters)`

Fetches specified user data fields from the `Users` and `profiledata` tables.

*   **Parameters:**
    *   `username` (str): The `UserName` of the user to fetch data for.
    *   `parameters` (list or str):
        *   A list of specific field names (strings) from either `Users` or `profiledata` tables (e.g., `["Role", "email", "FullName"]`). `Password` is excluded by default unless explicitly requested.
        *   The string `"profiledata"` to fetch all non-password `Users` fields and all `profiledata` fields.
*   **Returns:**
    *   `dict`: A dictionary containing the requested user data.
    *   `dict`: `{"error": "message"}` if the user is not found, parameters are invalid, or a database error occurs.
*   **Note:** Requires the `profiledata` table to exist with the expected columns if profile fields are requested.

**Usage:**

```python
from mbkauthe import get_user_data, validate_session
from flask import session, jsonify

@app.route('/my_profile_data')
@validate_session
def my_profile_data():
    username = session['user']['username']
    # Fetch specific fields
    data = get_user_data(username, ["FullName", "email", "Role", "AllowedApps"])
    if 'error' in data:
        return jsonify(data), 500 # Or handle error appropriately
    return jsonify(data)

@app.route('/full_profile/<target_username>')
@validate_session_and_role("SuperAdmin") # Example: Only admins can view full profiles
def view_full_profile(target_username):
    # Fetch all profile data
    data = get_user_data(target_username, "profiledata")
    if 'error' in data:
        return jsonify(data), 404 # User or profile might not exist
    return jsonify(data)
```

---

### `@authenticate_token`

Decorator to authenticate API requests based on a static token provided in the `Authorization` header.

*   It compares the value of the `Authorization` header directly against the `Main_SECRET_TOKEN` configured in the `.env` file's `mbkautheVar`.
*   If the token matches, the request proceeds.
*   If the token is missing or doesn't match, it returns a `401 Unauthorized` response.
*   **Use Case:** Primarily intended for protecting internal API endpoints that require server-to-server or administrative authentication, like `/mbkauthe/api/terminateAllSessions`.

**Usage:**

```python
from mbkauthe import authenticate_token

# This route is typically defined *within* mbkauthe/routes.py
# Example of how it's used there:
@mbkauthe_bp.route("/api/terminateAllSessions", methods=["POST"])
@authenticate_token # Apply decorator
def terminate_all_sessions():
    # Only requests with the correct Authorization header token reach here
    # ... logic to terminate sessions ...
    return jsonify({"success": True, "message": "All sessions terminated"})
```

---

## API Endpoints

These endpoints are automatically registered when you call `configure_mbkauthe(app)`. They are prefixed with `/mbkauthe`.

### Login

**POST** `/mbkauthe/api/login`

*   **Request Body (JSON):**
    *   `username` (str): User's username.
    *   `password` (str): User's **plaintext** password.
    *   `token` (str, optional): 2FA token if 2FA is enabled for the user.
    *   `recaptcha` (str, optional): Google reCAPTCHA response token if reCAPTCHA is enabled.
*   **Response:**
    *   `200 OK`: Login successful. Sets session cookie.
        ```json
        {
          "success": true,
          "message": "Login successful",
          "sessionId": "generated_session_id_string"
        }
        ```
    *   `400 Bad Request`: Missing username/password, missing reCAPTCHA, invalid input.
    *   `401 Unauthorized`: Incorrect username/password (errorCode 603), invalid 2FA token, 2FA required but not provided.
    *   `403 Forbidden`: Account inactive, user not authorized for the configured `APP_NAME`.
    *   `500 Internal Server Error`: Database error, unexpected bcrypt error (errorCode 605 if hash format invalid when `EncryptedPassword: true`), reCAPTCHA verification error.
    *   `501 Not Implemented`: Repository not configured (for image upload - *Note: This seems out of place for login, likely from image uploader context*).
    *   `503 Service Unavailable`: Database connection error.

### Logout

**POST** `/mbkauthe/api/logout`

*   **Request:** Sends existing session cookie automatically via browser or `-b cookies.txt` with curl.
*   **Response:**
    *   `200 OK`: Logout successful. Clears session cookie.
        ```json
        { "success": true, "message": "Logout successful" }
        ```
    *   `400 Bad Request`: User was not logged in (no valid session found).
    *   `500 Internal Server Error`: Database error during session clearing.

### Terminate All Sessions

**POST** `/mbkauthe/api/terminateAllSessions`

*   **Authentication:** Requires `Authorization` header matching `Main_SECRET_TOKEN` from `.env`. Use the `@authenticate_token` decorator.
*   **Action:** Clears `SessionId` for all users in the `Users` table and attempts to clear the server-side session store (e.g., truncates `session` table if using SQLAlchemy).
*   **Response:**
    *   `200 OK`: Sessions terminated.
        ```json
        { "success": true, "message": "All sessions terminated successfully" }
        ```
    *   `401 Unauthorized`: Missing or incorrect `Authorization` token.
    *   `500 Internal Server Error`: Database error during termination.

### Package Information

**GET** `/mbkauthe/package`

*   **Description**: Retrieves metadata about the installed `mbkauthe` package using `importlib.metadata`.
*   **Response**:
    *   `200 OK`: JSON object containing package metadata (name, version, dependencies, etc.).
    *   `404 Not Found`: If the `mbkauthe` package cannot be found by `importlib.metadata`.
    *   `500 Internal Server Error`: Other errors during metadata retrieval.

### Version Information

**GET** `/mbkauthe/version` or `/mbkauthe/v`

*   **Description**: Retrieves the current version string of the installed `mbkauthe` package.
*   **Response**:
    *   `200 OK`: JSON object `{ "version": "x.y.z" }`.
    *   `404 Not Found`: Package not found.
    *   `500 Internal Server Error`.

### Package Lock Information

**GET** `/mbkauthe/package-lock`

*   **Description**: Attempts to return information about `mbkauthe` from the project's lock file (`poetry.lock` or potentially `Pipfile.lock`). **Note:** This is less standard/reliable in Python than in Node.js. It might fail or return incomplete data if using `requirements.txt`. It prioritizes returning the library's *own* dependencies if parsing the project lock file fails.
*   **Response**:
    *   `200 OK`: JSON object with data found (either from lock file or library's own metadata).
    *   `404 Not Found`: Package not found.
    *   `501 Not Implemented`: If lock file parsing fails or isn't supported.
    *   `500 Internal Server Error`.

## Database Structure

This project utilizes the following primary tables in PostgreSQL:

*(Ensure your actual database schema matches these definitions, especially column names and types)*

### Users Table

Stores core user authentication and authorization information.

-   **Columns:**
    -   `id` (INTEGER, PRIMARY KEY, GENERATED ALWAYS AS IDENTITY): Unique identifier.
    -   `UserName` (TEXT, NOT NULL, UNIQUE): The username.
    -   `Password` (TEXT, NOT NULL): The user's password. **See Note on Passwords below.**
    -   `Role` (TEXT, NOT NULL, DEFAULT 'NormalUser', CHECK("Role" IN ('SuperAdmin', 'NormalUser', 'Guest'))): User role for permissions.
    -   `Active` (BOOLEAN, NOT NULL, DEFAULT true): Whether the account is enabled.
    -   `HaveMailAccount` (BOOLEAN, NOT NULL, DEFAULT false): Optional flag indicating a linked mail account.
    -   `SessionId` (TEXT): Stores the current unique session identifier upon successful login. Nullified on logout.
    -   `GuestRole` (JSONB, DEFAULT '{"allowPages": [""], "NotallowPages": [""]}'::jsonb): Optional, for guest-specific permissions (under construction).
    -   `AllowedApps` (JSONB, DEFAULT '["mbkauthe"]'::jsonb): A JSON array of application names the user is authorized to access (e.g., `["AppName1", "AppName2"]`). Checked during login and session validation unless the user `Role` is 'SuperAdmin'.

-   **Schema:**
    ```sql
    CREATE TABLE "Users" (
        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        "UserName" TEXT NOT NULL UNIQUE,
        "Password" TEXT NOT NULL,
        "Role" TEXT NOT NULL DEFAULT 'NormalUser'::text CHECK("Role" IN ('SuperAdmin', 'NormalUser', 'Guest')),
        "Active" BOOLEAN NOT NULL DEFAULT true,
        "HaveMailAccount" BOOLEAN NOT NULL DEFAULT false,
        "SessionId" TEXT,
        "GuestRole" JSONB DEFAULT '{"allowPages": [""], "NotallowPages": [""]}'::jsonb,
        "AllowedApps" JSONB DEFAULT '["mbkauthe"]'::jsonb
    );
    ```

### Session Table

Stores session data managed by Flask-Session. The exact schema depends on the `SESSION_TYPE` chosen.

-   **Schema (Example for `SESSION_TYPE="sqlalchemy"` - Requires table modification):**
    ```sql
    -- NOTE: If using the default SQLAlchemy interface, this table structure is expected.
    -- If using the custom interface with the original sid/sess/expire structure,
    -- this schema definition does NOT apply.
    CREATE TABLE session (
        id SERIAL PRIMARY KEY, -- Auto-incrementing integer ID
        session_id VARCHAR(255) UNIQUE NOT NULL, -- Stores the session key (e.g., 'session:...')
        data TEXT, -- Or BYTEA/BLOB depending on serialization
        expiry TIMESTAMP WITH TIME ZONE NOT NULL
    );
    CREATE INDEX ON session (session_id);
    CREATE INDEX ON session (expiry);
    ```
-   **Schema (Example for `SESSION_TYPE="custom"` using original Node.js structure):**
    ```sql
    -- This structure is used if you implement the CustomDbSessionInterface
    -- without altering the original table.
    CREATE TABLE session (
        sid VARCHAR PRIMARY KEY, -- Stores the session key (e.g., 'abc...')
        sess JSON NOT NULL, -- Stores session data as JSON
        expire TIMESTAMP WITH TIME ZONE NOT NULL
    );
    CREATE INDEX ON session (expire);
    ```

### Two-Factor Authentication (TwoFA) Table

Stores 2FA secrets and status for users who enable it.

-   **Columns:**
    -   `UserName` (TEXT, PRIMARY KEY, NOT NULL): Foreign key referencing `Users("UserName")`.
    -   `TwoFAStatus` (BOOLEAN, NOT NULL, DEFAULT false): Indicates if 2FA is currently enabled for the user.
    -   `TwoFASecret` (TEXT, NOT NULL): The base32 encoded secret key used for TOTP generation.

-   **Schema:**
    ```sql
    CREATE TABLE "TwoFA" (
        "UserName" TEXT NOT NULL PRIMARY KEY REFERENCES "Users"("UserName") ON DELETE CASCADE,
        "TwoFAStatus" BOOLEAN NOT NULL DEFAULT false,
        "TwoFASecret" TEXT NOT NULL
    );
    ```

### Profile Data Table

Stores additional, non-authentication profile information. Queried by `get_user_data`.

-   **Columns:** (Example - customize as needed)
    -   `UserName` (TEXT, PRIMARY KEY, NOT NULL): Foreign key referencing `Users("UserName")`.
    -   `FullName` (TEXT)
    -   `email` (TEXT)
    -   `Image` (TEXT)
    -   `ProjectLinks` (JSONB)
    -   `SocialAccounts` (JSONB)
    -   `Bio` (TEXT)
    -   `Positions` (JSONB)

-   **Schema (Example):**
    ```sql
    CREATE TABLE profiledata (
        "UserName" TEXT NOT NULL PRIMARY KEY REFERENCES "Users"("UserName") ON DELETE CASCADE,
        "FullName" TEXT,
        "email" TEXT,
        "Image" TEXT,
        "ProjectLinks" JSONB,
        "SocialAccounts" JSONB,
        "Bio" TEXT,
        "Positions" JSONB
    );
    ```

### Query to Add a User

Use SQL INSERT statements. **Handle passwords according to the `EncryptedPassword` setting.**

```sql
-- Example 1: Adding a user with a PLAINTEXT password
-- (Requires "EncryptedPassword": "false" in .env)
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "AllowedApps")
VALUES ('support', 'plaintext_password', 'SuperAdmin', true, '["YourAppName", "mbkauthe"]');

-- Example 2: Adding a user where the password should be BCRYPT HASHED
-- (Requires "EncryptedPassword": "true" in .env)
-- Step 1: Generate the hash using a script (see note below)
-- Step 2: Insert the generated hash
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "AllowedApps")
VALUES ('testuser', '$2b$12$YourGeneratedBcryptHashStringHere...', 'NormalUser', true, '["YourAppName"]');

-- Example 3: Adding 2FA info (optional)
INSERT INTO "TwoFA" ("UserName", "TwoFAStatus", "TwoFASecret")
VALUES ('testuser', true, 'BASE32SECRETKEYHERE');

-- Example 4: Adding profile data (optional)
INSERT INTO profiledata ("UserName", "FullName", "email")
VALUES ('testuser', 'Test User', 'test@example.com');
```

### Important Note on Passwords

The `mbkauthe` package handles **either** plaintext or bcrypt hashed passwords stored in `Users.Password`.

*   **Configuration:** Controlled by `"EncryptedPassword"` in `.env`.
    *   `"false"`: Store plaintext. **(Less Secure)**
    *   `"true"`: Store bcrypt hashes. **(Recommended)**
*   **Consistency:** Ensure the config **matches** the database storage method.
*   **Generating Hashes:** If using `"EncryptedPassword": "true"`, **never** store plaintext. Generate hashes using `bcrypt.hashpw(password_bytes, bcrypt.gensalt())` before inserting.

## License

This project is licensed under the `Mozilla Public License 2.0`. See the LICENSE file for details.

## 📬 Contact & Support

Created by **Maaz Waheed**  
GitHub: [@42Wor](https://github.com/42Wor)
