# mbkauthe/routes.py (Full file with conditional password check)

import logging
from flask import Blueprint, request, jsonify, session, make_response, current_app, render_template,render_template_string
import psycopg2
import psycopg2.extras
import bcrypt # <-- Re-add bcrypt import
import requests
import pyotp
import secrets
import importlib.metadata
import json
import os
# import toml # Only needed if parsing poetry.lock below

# Import local modules
from .db import get_db_connection, release_db_connection
# Import middleware and utils needed for routes
from .middleware import authenticate_token, validate_session # Assuming these exist
from .utils import get_cookie_options # Assuming this exists

logger = logging.getLogger(__name__)

# Define the Blueprint
mbkauthe_bp = Blueprint('mbkauthe', __name__, url_prefix='/mbkauthe', template_folder='templates')

# --- Middleware for Session Cookie Update ---
@mbkauthe_bp.after_request
def after_request_callback(response):
    # This hook runs after each request within this blueprint
    if 'user' in session and session.get('user'):
        user_info = session['user']
        # Set non-httpOnly cookie for username (if needed by frontend JS)
        # Ensure get_cookie_options is available and working
        try:
            cookie_opts_no_http = get_cookie_options(http_only=False)
            cookie_opts_http = get_cookie_options(http_only=True)
            response.set_cookie("username", user_info.get('username', ''), **cookie_opts_no_http)
            response.set_cookie("sessionId", user_info.get('sessionId', ''), **cookie_opts_http)
        except NameError:
             logger.error("get_cookie_options function not found or not imported correctly.")
        except Exception as e:
             logger.error(f"Error setting cookies in after_request: {e}")

    # Add security headers (optional but good practice)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP

    return response

# --- API Routes ---

@mbkauthe_bp.route("/api/login", methods=["POST"])
def login():
    # --- Get Configuration ---
    try:
        config = current_app.config["MBKAUTHE_CONFIG"]
    except KeyError:
        logger.error("MBKAUTHE_CONFIG not found in Flask app config. Ensure configure_mbkauthe ran correctly.")
        return jsonify({"success": False, "message": "Server configuration error."}), 500

    # --- Get Request Data ---
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request body (expecting JSON)"}), 400

    username = data.get("username")
    password = data.get("password")
    token_2fa = data.get("token")
    recaptcha_response = data.get("recaptcha")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    # --- reCAPTCHA Verification ---
    bypass_users = config.get("BypassUsers", [])
    if config.get("RECAPTCHA_Enabled", False) and username not in bypass_users:
        if not recaptcha_response:
            logger.warning("Login failed: Missing reCAPTCHA token")
            return jsonify({"success": False, "message": "Please complete the reCAPTCHA"}), 400

        secret_key = config.get("RECAPTCHA_SECRET_KEY")
        if not secret_key:
             logger.error("reCAPTCHA enabled but RECAPTCHA_SECRET_KEY is missing in config.")
             return jsonify({"success": False, "message": "Server configuration error."}), 500

        verification_url = f"https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={recaptcha_response}"
        try:
            response = requests.post(verification_url, timeout=10)
            response.raise_for_status()
            result = response.json()
            logger.debug(f"reCAPTCHA verification response: {result}")
            if not result.get("success"):
                logger.warning("Login failed: Failed reCAPTCHA verification")
                error_codes = result.get('error-codes', [])
                logger.warning(f"reCAPTCHA error codes: {error_codes}")
                return jsonify({"success": False, "message": f"Failed reCAPTCHA verification. {error_codes}"}), 400
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during reCAPTCHA verification: {e}")
            return jsonify({"success": False, "message": "reCAPTCHA check failed. Please try again."}), 500

    # --- User Authentication ---
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Fetch user data
            user_query = """
                SELECT u.id, u."UserName", u."Password", u."Role", u."Active", u."AllowedApps",
                       tfa."TwoFAStatus", tfa."TwoFASecret", u."SessionId"
                FROM "Users" u
                LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
                WHERE u."UserName" = %s
            """
            cur.execute(user_query, (username,))
            user = cur.fetchone()

            if not user:
                logger.warning(f"Login failed: Username does not exist: {username}")
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401

            # --- Password Check ---
            stored_password = user["Password"]
            use_encryption = config.get("EncryptedPassword", False)
            password_match = False

            logger.info(f"Password check mode: {'Encrypted' if use_encryption else 'Plaintext'}")

            if use_encryption:
                try:
                    password_bytes = password.encode('utf-8')
                    stored_password_bytes = stored_password.encode('utf-8') if isinstance(stored_password, str) else stored_password
                    password_match = bcrypt.checkpw(password_bytes, stored_password_bytes)
                    if password_match:
                         logger.info("Encrypted password matches!")
                    else:
                         logger.warning(f"Encrypted password check failed for {username}")
                except ValueError as e:
                    logger.error(f"Error comparing password for {username}: {e}. Check password hash format in DB.")
                    return jsonify({"success": False, "errorCode": 605, "message": "Internal Server Error during auth (bcrypt format error)"}), 500
                except Exception as e:
                    logger.error(f"Unexpected error during encrypted password check for {username}: {e}", exc_info=True)
                    return jsonify({"success": False, "errorCode": 605, "message": "Internal Server Error during auth (bcrypt unexpected error)"}), 500
            else:
                logger.info(f"Performing PLAINTEXT password check for {username}")
                password_match = (password == stored_password)
                if password_match:
                     logger.info("Plaintext password matches!")
                else:
                     logger.warning(f"Plaintext password check failed for {username}.")

            if not password_match:
                 logger.warning(f"Login failed: Incorrect password for username: {username}")
                 return jsonify({"success": False, "errorCode": 603, "message": "Incorrect Username Or Password"}), 401

            # --- Account Status Check ---
            if not user["Active"]:
                logger.warning(f"Login failed: Inactive account for username: {username}")
                return jsonify({"success": False, "message": "Account is inactive"}), 403

            # --- Application Access Check ---
            if user["Role"] != "SuperAdmin":
                allowed_apps = user.get("AllowedApps") or []
                app_name = config.get("APP_NAME", "UNKNOWN_APP")
            if app_name.lower() not in [a.lower() for a in allowed_apps]:
                    logger.warning(f"Login failed: User '{username}' not authorized for app '{app_name}'. Allowed: {allowed_apps}")
                    return jsonify({"success": False, "message": f"You Are Not Authorized To Use The Application \"{app_name}\""}), 403

            # --- Two-Factor Authentication (2FA) Check ---
            if config.get("MBKAUTH_TWO_FA_ENABLE", False):
                two_fa_status = user.get("TwoFAStatus", False)
                two_fa_secret = user.get("TwoFASecret")
                if two_fa_status:
                    if not token_2fa:
                        logger.warning(f"Login failed: 2FA code required but not provided for {username}")
                        return jsonify({"success": False, "message": "Please Enter 2FA code", "requires2FA": True}), 401
                    if not two_fa_secret:
                         logger.error(f"Login failed: 2FA enabled for {username} but no secret found in DB.")
                         return jsonify({"success": False, "message": "2FA configuration error"}), 500
                    try:
                        totp = pyotp.TOTP(two_fa_secret)
                        if not totp.verify(token_2fa, valid_window=1):
                            logger.warning(f"Login failed: Invalid 2FA code for username: {username}")
                            return jsonify({"success": False, "message": "Invalid 2FA code"}), 401
                        logger.info(f"2FA verification successful for {username}")
                    except Exception as e:
                         logger.error(f"Error during 2FA verification for {username}: {e}")
                         return jsonify({"success": False, "message": "Error verifying 2FA code"}), 500

            # --- Session Management ---
            session_id = secrets.token_hex(32)
            logger.info(f"Generated session ID for username: {username}")

            # Delete old session record for this user if using a session table (optional)
            if user.get("SessionId"):
                try:
                    cur.execute('DELETE FROM "session" WHERE username = %s', (user["UserName"],))
                    logger.info(f"Deleted old session record for user: {username}")
                except Exception as e:
                    logger.warning(f"Could not delete old session record for user {username}: {e}")

            # Update SessionId in the database
            update_query = 'UPDATE "Users" SET "SessionId" = %s WHERE "id" = %s'
            cur.execute(update_query, (session_id, user["id"]))
            conn.commit()

            # Store user info in Flask session
            session.clear()
            session['user'] = {
                'id': user['id'],
                'username': user['UserName'],
                'role': user['Role'],
                'sessionId': session_id
            }
            session.permanent = True

            # Optionally update username in session table if using Flask-Session SQLAlchemy
            try:
                cur.execute('UPDATE "session" SET username = %s WHERE sid = %s', (user["UserName"], session_id))
                conn.commit()
            except Exception as e:
                logger.warning(f"Failed to update username in session table: {e}")

            logger.info(f"User '{username}' logged in successfully (Password Check Mode: {'Encrypted' if use_encryption else 'Plaintext'})")

            # Prepare response
            response_data = {
                "success": True,
                "message": "Login successful",
                "sessionId": session_id
            }
            resp = make_response(jsonify(response_data), 200)
            return resp

    except ConnectionError as e:
         logger.error(f"Database connection error during login for {username}: {e}")
         return jsonify({"success": False, "message": "Database connection error"}), 503
    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error during login process for {username}: {e}", exc_info=True)
        if conn:
            try:
                conn.rollback()
            except Exception as rb_err:
                 logger.error(f"Error during rollback: {rb_err}")
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)


@mbkauthe_bp.route("/api/logout", methods=["POST"])
@validate_session # Ensure user is logged in to log out
def logout():
    # ... (logout logic as provided before) ...
    if 'user' in session:
        user_info = session['user']
        user_id = user_info.get('id')
        username = user_info.get('username', 'N/A')
        logger.info(f"Logout request for user: {username} (ID: {user_id})")
        conn = None
        try:
            if user_id:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('UPDATE "Users" SET "SessionId" = NULL WHERE "id" = %s', (user_id,))
                conn.commit()
                logger.info(f"Cleared SessionId in DB for user ID: {user_id}")
            session.clear()
            resp = make_response(jsonify({"success": True, "message": "Logout successful"}), 200)
            cookie_options = get_cookie_options()
            resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            logger.info(f"User '{username}' logged out successfully")
            return resp
        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"Database error during logout for user {username}: {e}")
            if conn: conn.rollback()
            session.clear()
            resp = make_response(jsonify({"success": False, "message": "Internal Server Error during logout"}), 500)
            cookie_options = get_cookie_options()
            resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            return resp
        finally:
            if conn: release_db_connection(conn)
    else:
        logger.warning("Logout attempt failed: No active session found.")
        resp = make_response(jsonify({"success": False, "message": "Not logged in"}), 400)
        cookie_options = get_cookie_options()
        resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        return resp


@mbkauthe_bp.route("/api/terminateAllSessions", methods=["POST"])
@authenticate_token
def terminate_all_sessions():
    logger.warning("Received request to terminate all user sessions.")
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('UPDATE "Users" SET "SessionId" = NULL')
            users_updated = cur.rowcount
            logger.info(f"Cleared SessionId for {users_updated} users.")

            cur.execute('DELETE FROM "session"')
            logger.info('Deleted all records from "session" table.')

        conn.commit()
        # Destroy the current session
        session.clear()

        resp = make_response(jsonify({
            "success": True,
            "message": "All sessions terminated successfully"
        }), 200)
        cookie_options = get_cookie_options()
        resp.delete_cookie("mbkauthe.sid", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        logger.info("All sessions terminated successfully")
        return resp

    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Database query error during session termination: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)

@mbkauthe_bp.route("/info", methods=["GET"])
@mbkauthe_bp.route("/i", methods=["GET"])
def mbkauthe_info():
    package_name = "mbkauthepy"
    config = current_app.config.get("MBKAUTHE_CONFIG", {})

    # Get current version
    try:
        version = importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        version = "Unknown"
        logger.warning(f"Package {package_name} not found")

    # Get latest version from PyPI
    latest_version = None
    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=5
        )
        resp.raise_for_status()
        latest_version = resp.json().get("info", {}).get("version")
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch latest version from PyPI: {e}")

    # Get package metadata
    try:
        metadata = importlib.metadata.metadata(package_name)
        package_json = {k: str(metadata[k]) for k in metadata.keys()}
    except importlib.metadata.PackageNotFoundError:
        package_json = {}
        logger.warning(f"Failed to fetch metadata for {package_name}")

    # Get dependencies
    try:
        dependencies = metadata.get_all("Requires-Dist", []) if metadata else []
    except Exception as e:
        dependencies = []
        logger.warning(f"Failed to fetch dependencies: {e}")

    # Configuration info
    info = {
        "APP_NAME": config.get("APP_NAME", "N/A"),
        "RECAPTCHA_Enabled": config.get("RECAPTCHA_Enabled", False),
        "MBKAUTH_TWO_FA_ENABLE": config.get("MBKAUTH_TWO_FA_ENABLE", False),
        "COOKIE_EXPIRE_TIME": config.get("COOKIE_EXPIRE_TIME", "N/A"),
        "IS_DEPLOYED": config.get("IS_DEPLOYED", False),
        "DOMAIN": config.get("DOMAIN", "N/A"),
    }

    # HTML template for Version and Configuration Dashboard with modern styling and accessibility
    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Version and Configuration Dashboard</title>
    <style>
        :root {
                --bg-color: #18181b;
                --text-color: #f3f4f6;
                --container-bg: linear-gradient(135deg, #232946 60%, #393e46 100%);
            --accent-color: #7b2cbf;
            --accent-hover: #9d4edd;
            --label-color: #b0b0b0;
                --json-bg: #232946;
            --json-text: #a3e635;
            --success-color: #00cc00;
            --warning-color: #ff9500;
            --error-color: #ff3d3d;
                --border-radius: 14px;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            background: var(--bg-color);
            color: var(--text-color);
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
                justify-content: center;
                padding: 24px;
        }
        .container {
                max-width: 900px;
                width: 100%;
            background: var(--container-bg);
                border-radius: var(--border-radius);
                padding: 2.5rem 2rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.35);
                animation: fadeIn 0.5s;
        }
        h1 {
            color: var(--accent-color);
                font-size: 2.3rem;
            margin-bottom: 1.5rem;
            text-align: center;
            text-transform: uppercase;
                letter-spacing: 1.5px;
            background: linear-gradient(90deg, var(--accent-color), var(--accent-hover));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .info-section {
            margin-bottom: 2rem;
                border: 1px solid rgba(255,255,255,0.08);
            border-radius: 10px;
                padding: 1.5rem 1.2rem;
                background: rgba(35,35,70,0.7);
                transition: box-shadow 0.3s;
        }
            .info-section:focus-within, .info-section:hover {
                box-shadow: 0 4px 16px rgba(123,44,191,0.18);
        }
        h2 {
            color: var(--text-color);
                font-size: 1.35rem;
            margin-bottom: 1rem;
            border-bottom: 2px solid var(--accent-color);
                padding-bottom: 0.4rem;
        }
        .info-label {
            font-weight: 600;
            color: var(--label-color);
                min-width: 180px;
            display: inline-block;
                font-size: 1rem;
        }
        .info-row {
            display: flex;
            align-items: center;
                margin-bottom: 0.7rem;
                padding: 0.4rem 0.2rem;
            border-radius: 6px;
                transition: background 0.2s;
        }
        .info-row:hover {
                background: rgba(255,255,255,0.04);
        }
        .json-container {
            background: var(--json-bg);
            border-radius: 8px;
                padding: 1.1rem;
                font-family: 'Fira Code', 'Consolas', monospace;
                font-size: 0.97rem;
            color: var(--json-text);
            overflow-x: auto;
            white-space: pre-wrap;
                max-height: 260px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--accent-color) var(--json-bg);
        }
        .json-container::-webkit-scrollbar {
            width: 8px;
        }
        .json-container::-webkit-scrollbar-thumb {
            background: var(--accent-color);
            border-radius: 4px;
        }
        .status-up-to-date { 
            color: var(--success-color);
            font-weight: 600;
            animation: pulse 2s infinite;
        }
        .status-update-available { 
            color: var(--error-color);
            font-weight: 600;
        }
        .status-unknown { 
            color: var(--warning-color);
            font-weight: 600;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        @media (max-width: 768px) {
            .container {
                    padding: 1.2rem 0.5rem;
            }
            h1 {
                    font-size: 1.5rem;
            }
            .info-label {
                min-width: 100%;
                    margin-bottom: 0.2rem;
            }
            .info-row {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
        <div class="container" role="main">
        <h1>Version and Configuration Dashboard</h1>
            <div class="info-section" tabindex="0">
            <h2>Version Information</h2>
            <div class="info-row">
                <span class="info-label">Current Version:</span> 
                <span>{{ version | e }}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Latest Version:</span> 
                <span>{{ latest_version or 'Could not fetch latest version' | e }}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Status:</span>
                    <span class="{% if latest_version and version == latest_version %}status-up-to-date{% elif latest_version %}status-update-available{% else %}status-unknown{% endif %}">
                    {% if latest_version and version == latest_version %}
                        Up to date
                    {% elif latest_version %}
                        Update available
                    {% else %}
                        Unknown
                    {% endif %}
                </span>
            </div>
        </div>
            <div class="info-section" tabindex="0">
            <h2>Configuration Information</h2>
            {% for key, value in info.items() %}
                <div class="info-row">
                    <span class="info-label">{{ key | e }}:</span>
                    <span>{{ value | e }}</span>
                </div>
            {% endfor %}
        </div>
            <div class="info-section" tabindex="0">
            <h2>Package Metadata</h2>
            <div class="json-container">
                <pre>{{ package_json | tojson(indent=2) | e }}</pre>
            </div>
        </div>
            <div class="info-section" tabindex="0">
            <h2>Dependencies</h2>
            <div class="json-container">
                <pre>{{ dependencies | tojson(indent=2) | e }}</pre>
            </div>
        </div>
    </div>
</body>
</html>
"""

    return render_template_string(
        template,
        version=version,
        latest_version=latest_version,
        info=info,
        package_json=package_json,
        dependencies=dependencies
    )