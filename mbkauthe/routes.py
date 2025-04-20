import logging
from flask import Blueprint, request, jsonify, session, make_response, current_app, render_template
import psycopg2
import psycopg2.extras
import bcrypt
import requests
import pyotp
import secrets # Python's modern crypto module for tokens
import importlib.metadata # For package version
import json
import os
#import path # For reading package-lock.json (if needed, see notes)

from .db import get_db_connection, release_db_connection
from .middleware import authenticate_token, validate_session # Import necessary middleware
from .utils import get_cookie_options

logger = logging.getLogger(__name__)

mbkauthe_bp = Blueprint('mbkauthe', __name__, url_prefix='/mbkauthe', template_folder='templates')

# --- CORS Handling (Apply to Blueprint or App) ---
# from flask_cors import CORS
# CORS(mbkauthe_bp, supports_credentials=True, origins=["*.yourdomain.com"]) # Adjust origins

# --- Middleware for Session Cookie Update ---
@mbkauthe_bp.after_request
def after_request_callback(response):
    # Ensure session cookie reflects changes, Flask-Session usually handles this
    # Manually set username/sessionId cookies if needed after login/session restoration
    if 'user' in session and session.get('user'):
        user_info = session['user']
        # Set non-httpOnly cookie for username (if needed by frontend JS)
        response.set_cookie("username", user_info.get('username', ''), **get_cookie_options(http_only=False))
        # Set httpOnly cookie for sessionId (redundant if session restored from it, but good practice)
        response.set_cookie("sessionId", user_info.get('sessionId', ''), **get_cookie_options(http_only=True))
    elif request.endpoint and 'logout' not in request.endpoint: # Avoid setting on logout response
         # If no user in session, try to clear cookies if they exist but session is invalid
         # This logic might be better placed within validate_session error handling
         pass

    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP

    return response

@mbkauthe_bp.route("/api/login", methods=["POST"])
def login():
    config = current_app.config["MBKAUTHE_CONFIG"]
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request body"}), 400

    username = data.get("username")
    password = data.get("password") # User submitted password (plain text)
    token_2fa = data.get("token") # 2FA token
    recaptcha_response = data.get("recaptcha")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    # --- reCAPTCHA Verification ---
    bypass_users = config.get("BypassUsers", [])
    if config["RECAPTCHA_Enabled"] and username not in bypass_users:
        if not recaptcha_response:
            logger.warning("Login failed: Missing reCAPTCHA token")
            return jsonify({"success": False, "message": "Please complete the reCAPTCHA"}), 400

        secret_key = config.get("RECAPTCHA_SECRET_KEY")
        verification_url = f"https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={recaptcha_response}"
        try:
            response = requests.post(verification_url, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            result = response.json()
            logger.debug(f"reCAPTCHA verification response: {result}")
            if not result.get("success"):
                logger.warning("Login failed: Failed reCAPTCHA verification")
                return jsonify({"success": False, "message": "Failed reCAPTCHA verification"}), 400
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during reCAPTCHA verification: {e}")
            return jsonify({"success": False, "message": "reCAPTCHA check failed. Please try again."}), 500

    # --- User Authentication ---
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Fetch user including password and 2FA status/secret
            user_query = """
                SELECT u.id, u."UserName", u."Password", u."Role", u."Active", u."AllowedApps",
                       tfa."TwoFAStatus", tfa."TwoFASecret"
                FROM "Users" u
                LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
                WHERE u."UserName" = %s
            """
            cur.execute(user_query, (username,))
            user = cur.fetchone()

            if not user:
                logger.warning(f"Login failed: Username does not exist: {username}")
                # Generic message for security
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401 # 401 Unauthorized

            # --- Password Check (Direct Comparison - INSECURE) ---
            # **SECURITY WARNING:** Comparing plaintext passwords is highly insecure.
            # This modification implements the user's request but is STRONGLY discouraged.
            db_password = user["Password"] # Get the plain text password stored in the database

            # Direct string comparison:
            if password != db_password:
                logger.warning(f"Login failed: Incorrect password for username: {username}")
                # Use a generic message to avoid revealing which part (user/pass) was wrong
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401 # 401 Unauthorized
            # If the comparison passes, execution continues.
            # logger.info("Password matches!") # Logging success at the end is better

            # --- Account Status Check ---
            if not user["Active"]:
                logger.warning(f"Login failed: Inactive account for username: {username}")
                return jsonify({"success": False, "message": "Account is inactive"}), 403 # 403 Forbidden

            # --- Application Access Check ---
            if user["Role"] != "SuperAdmin":
                allowed_apps = user["AllowedApps"] or []
                app_name = config["APP_NAME"]
                if app_name not in allowed_apps:
                    logger.warning(f"Login failed: User '{username}' not authorized for app '{app_name}'.")
                    return jsonify({"success": False, "message": f"You Are Not Authorized To Use The Application \"{app_name}\""}), 403

            # --- Two-Factor Authentication (2FA) Check ---
            if config["MBKAUTH_TWO_FA_ENABLE"]:
                two_fa_status = user.get("TwoFAStatus", False)
                two_fa_secret = user.get("TwoFASecret")

                if two_fa_status: # If 2FA is enabled for this user
                    if not token_2fa:
                        logger.warning(f"Login failed: 2FA code required but not provided for {username}")
                        # Indicate 2FA is needed
                        return jsonify({"success": False, "message": "Please Enter 2FA code", "requires2FA": True}), 401
                    if not two_fa_secret:
                         logger.error(f"Login failed: 2FA enabled for {username} but no secret found in DB.")
                         return jsonify({"success": False, "message": "2FA configuration error"}), 500

                    # Verify the token
                    totp = pyotp.TOTP(two_fa_secret)
                    if not totp.verify(token_2fa):
                        logger.warning(f"Login failed: Invalid 2FA code for username: {username}")
                        return jsonify({"success": False, "message": "Invalid 2FA code"}), 401
                    logger.info(f"2FA verification successful for {username}")


            # --- Login Success: Generate Session ---
            session_id = secrets.token_hex(32) # Generate a secure random session ID
            logger.info(f"Generated session ID for username: {username}")

            # Update SessionId in the database
            update_query = 'UPDATE "Users" SET "SessionId" = %s WHERE "id" = %s'
            cur.execute(update_query, (session_id, user["id"]))
            conn.commit() # Commit the transaction

            # Store user info in Flask session
            session.clear() # Clear any old session data first
            session['user'] = {
                'id': user['id'],
                'username': user['UserName'],
                'role': user['Role'],
                'sessionId': session_id # Store session ID in Flask session as well
            }
            session.permanent = True # Make the session persistent based on app config lifetime

            logger.info(f"User '{username}' logged in successfully")

            # Prepare response
            response_data = {
                "success": True,
                "message": "Login successful",
                "sessionId": session_id # Include session ID in response body if needed by client
            }
            resp = make_response(jsonify(response_data), 200)

            # Set cookies using helper function (ensure it's defined correctly)
            # Example: You might set cookies like this if needed, often done in after_request
            # resp.set_cookie("sessionId", session_id, **get_cookie_options(http_only=True))
            # resp.set_cookie("username", user['UserName'], **get_cookie_options(http_only=False))

            return resp

    except (Exception, psycopg2.DatabaseError) as e:
        logger.exception(f"Error during login process for {username}: {e}") # Use logger.exception to include traceback
        if conn:
            conn.rollback() # Rollback transaction on error
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)
@mbkauthe_bp.route("/api/logout", methods=["POST"])
@validate_session # Ensure user is logged in to log out
def logout():
    if 'user' in session:
        user_info = session['user']
        user_id = user_info.get('id')
        username = user_info.get('username', 'N/A')
        logger.info(f"Logout request for user: {username} (ID: {user_id})")

        conn = None
        try:
            # Clear SessionId in the database
            if user_id:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('UPDATE "Users" SET "SessionId" = NULL WHERE "id" = %s', (user_id,))
                conn.commit()
                logger.info(f"Cleared SessionId in DB for user ID: {user_id}")

            # Clear the Flask session
            session.clear()

            # Prepare response and clear cookies
            resp = make_response(jsonify({"success": True, "message": "Logout successful"}), 200)
            cookie_options = get_cookie_options() # Get base options
            resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            # Flask-Session handles its own cookie ('mbkauthe.sid') deletion on session.clear()

            logger.info(f"User '{username}' logged out successfully")
            return resp

        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"Database error during logout for user {username}: {e}")
            if conn:
                conn.rollback()
            # Still clear local session even if DB update fails? Maybe.
            session.clear()
            # Return error but potentially clear cookies anyway
            resp = make_response(jsonify({"success": False, "message": "Internal Server Error during logout"}), 500)
            cookie_options = get_cookie_options()
            resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
            return resp
        finally:
            if conn:
                release_db_connection(conn)
    else:
        # User was not logged in according to the session
        logger.warning("Logout attempt failed: No active session found.")
        resp = make_response(jsonify({"success": False, "message": "Not logged in"}), 400)
        # Clear any potentially lingering cookies
        cookie_options = get_cookie_options()
        resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        return resp


@mbkauthe_bp.route("/api/terminateAllSessions", methods=["POST"])
@authenticate_token # Use the token authentication middleware
def terminate_all_sessions():
    logger.warning("Received request to terminate all user sessions.")
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Clear SessionId for all users
            cur.execute('UPDATE "Users" SET "SessionId" = NULL')
            users_updated = cur.rowcount
            logger.info(f"Cleared SessionId for {users_updated} users.")

            # Clear the server-side session store (e.g., truncate session table)
            # This depends heavily on the Flask-Session backend used.
            session_table = current_app.config["MBKAUTHE_CONFIG"].get("SESSION_SQLALCHEMY_TABLE", "session")
            if current_app.config["MBKAUTHE_CONFIG"].get("SESSION_TYPE") == "sqlalchemy":
                 # Be CAREFUL with TRUNCATE in production!
                 # Consider DELETE FROM session WHERE expiry < NOW() instead?
                 # Or just let sessions expire naturally after SessionId is NULL.
                 # Truncating is faster but more aggressive.
                 cur.execute(f'TRUNCATE TABLE "{session_table}" RESTART IDENTITY') # Use TRUNCATE if safe and desired
                 # cur.execute(f'DELETE FROM "{session_table}"') # Safer alternative
                 logger.info(f"Cleared session table '{session_table}'.")
            else:
                 logger.warning(f"Session termination for non-SQLAlchemy backend ('{current_app.config['MBKAUTHE_CONFIG'].get('SESSION_TYPE')}') needs manual implementation.")
                 # E.g., for Redis: flushdb or delete keys matching a pattern
                 # E.g., for Filesystem: delete files in session directory

        conn.commit()

        # Clear the current request's session just in case the admin was logged in
        session.clear()

        # Prepare response and clear cookies for the current request
        resp = make_response(jsonify({
            "success": True,
            "message": "All sessions terminated successfully"
        }), 200)
        cookie_options = get_cookie_options()
        resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        # Flask-Session handles its own cookie

        logger.warning("All user sessions terminated successfully.")
        return resp

    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error during terminateAllSessions: {e}")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error during session termination"}), 500
    finally:
        if conn:
            release_db_connection(conn)


# --- Informational Endpoints ---

@mbkauthe_bp.route("/package", methods=["GET"])
def package_info():
    """Returns metadata about the installed mbkauthe package."""
    try:
        # Get metadata using importlib.metadata
        metadata = importlib.metadata.metadata("mbkauthe")
        # Convert email.message.Message to dict
        package_data = {key: metadata[key] for key in metadata.keys()}
        return jsonify(package_data)
    except importlib.metadata.PackageNotFoundError:
        logger.error("Could not find metadata for 'mbkauthe' package.")
        return jsonify({"success": False, "message": "Package 'mbkauthe' not found"}), 404
    except Exception as e:
        logger.error(f"Error retrieving package metadata: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@mbkauthe_bp.route("/version", methods=["GET"])
@mbkauthe_bp.route("/v", methods=["GET"])
def version_info():
    """Returns the version of the installed mbkauthe package."""
    try:
        version = importlib.metadata.version("mbkauthe")
        return jsonify({"version": version})
    except importlib.metadata.PackageNotFoundError:
        logger.error("Could not find version for 'mbkauthe' package.")
        return jsonify({"success": False, "message": "Package 'mbkauthe' not found"}), 404
    except Exception as e:
        logger.error(f"Error retrieving package version: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@mbkauthe_bp.route("/package-lock", methods=["GET"])
def package_lock_info():
    """
    Attempts to return information about mbkauthe from the project's lock file.
    NOTE: This is less standard in Python and depends on the project using Poetry or pipenv.
    It might fail or return incomplete data if using requirements.txt.
    Returning the library's *own* dependencies is more reliable.
    """
    logger.info("Request for package-lock equivalent received.")

    # Option 1: Return library's own dependencies (more reliable)
    try:
        metadata = importlib.metadata.metadata("mbkauthe")
        dependencies = metadata.get_all("Requires-Dist")
        return jsonify({
            "message": "Returning library's own dependencies",
            "name": metadata.get("Name"),
            "version": metadata.get("Version"),
            "dependencies": dependencies or []
        })

    except importlib.metadata.PackageNotFoundError:
         return jsonify({"success": False, "message": "Package 'mbkauthe' not found"}), 404
    except Exception as e:
         logger.error(f"Error retrieving library dependencies: {e}")
         # Fall through to attempt reading project lock file, or return error


    # Option 2: Try to find and parse project's lock file (less reliable)
    # This requires making assumptions about the project structure
    project_root = os.getcwd() # Or determine differently
    poetry_lock_path = os.path.join(project_root, "poetry.lock")
    # pipfile_lock_path = os.path.join(project_root, "Pipfile.lock") # If using pipenv

    lock_data = None
    lock_file_type = None

    if os.path.exists(poetry_lock_path):
        # Parsing TOML requires a library like 'toml'
        # pip install toml
        try:
            import toml
            with open(poetry_lock_path, 'r') as f:
                lock_data = toml.load(f)
            lock_file_type = "poetry.lock"
            # Extract mbkauthe info from lock_data['package'] list
            mbkauthe_info = next((pkg for pkg in lock_data.get('package', []) if pkg.get('name') == 'mbkauthe'), None)
            if mbkauthe_info:
                 return jsonify({"source": lock_file_type, "mbkautheData": mbkauthe_info})
            else:
                 return jsonify({"success": False, "source": lock_file_type, "message": "mbkauthe not found in lock file"}), 404

        except ImportError:
            logger.warning("Cannot parse poetry.lock: 'toml' library not installed.")
            return jsonify({"success": False, "message": "Cannot parse poetry.lock: 'toml' library not installed."}), 501 # Not Implemented
        except Exception as e:
            logger.error(f"Error reading/parsing {poetry_lock_path}: {e}")
            return jsonify({"success": False, "message": f"Failed to read or parse {lock_file_type}"}), 500

    # Add similar logic for Pipfile.lock if needed

    logger.warning("Could not find or parse a known project lock file (poetry.lock).")
    return jsonify({"success": False, "message": "Could not determine project dependencies for mbkauthe"}), 501 # Not Implemented