# mbkauthe/routes.py (Full file with conditional password check)

import logging
from flask import Blueprint, request, jsonify, session, make_response, current_app, render_template
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
    password = data.get("password") # User submitted password (plaintext)
    token_2fa = data.get("token")
    recaptcha_response = data.get("recaptcha")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    # --- reCAPTCHA Verification ---
    bypass_users = config.get("BypassUsers", [])
    # Use .get for boolean flags with a default
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
    # --- End reCAPTCHA ---

    # --- User Authentication ---
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Fetch user data
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
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401

            # --- !!! CONDITIONAL PASSWORD CHECK !!! ---
            stored_password = user["Password"] # Password from DB (could be hash or plaintext)
            use_encryption = config.get("EncryptedPassword", False) # Get flag from config
            password_match = False

            logger.info(f"Password check mode: {'Encrypted' if use_encryption else 'Plaintext'}")

            if use_encryption:
                # --- Encrypted (bcrypt) Check ---
                try:
                    password_bytes = password.encode('utf-8')
                    # Ensure stored password is bytes if it's a string hash from DB
                    stored_password_bytes = stored_password.encode('utf-8') if isinstance(stored_password, str) else stored_password

                    # Perform the bcrypt check
                    password_match = bcrypt.checkpw(password_bytes, stored_password_bytes)

                    if password_match:
                         logger.info("Encrypted password matches!")
                    else:
                         logger.warning(f"Encrypted password check failed for {username}")

                except ValueError as e:
                    # This specific error often means the stored hash is invalid (e.g., plaintext stored when hash expected)
                    logger.error(f"Error comparing password for {username}: {e}. Check password hash format in DB.")
                    # Return 605 ONLY if encryption was attempted and failed due to format
                    return jsonify({"success": False, "errorCode": 605, "message": "Internal Server Error during auth (bcrypt format error)"}), 500
                except Exception as e:
                    # Catch other potential bcrypt errors
                    logger.error(f"Unexpected error during encrypted password check for {username}: {e}", exc_info=True)
                    return jsonify({"success": False, "errorCode": 605, "message": "Internal Server Error during auth (bcrypt unexpected error)"}), 500
            else:
                # --- Plaintext Check ---
                logger.info(f"Performing PLAINTEXT password check for {username}")
                # Direct string comparison
                password_match = (password == stored_password)
                if password_match:
                     logger.info("Plaintext password matches!")
                else:
                     logger.warning(f"Plaintext password check failed for {username}.")
                     # Optional: Log passwords only in secure debug environments if absolutely needed
                     # logger.debug(f"Provided: '{password}', Stored: '{stored_password}'")

            # --- Check Result (Common for both methods) ---
            if not password_match:
                 logger.warning(f"Login failed: Incorrect password for username: {username}")
                 # Use 603 for general incorrect password after check
                 return jsonify({"success": False, "errorCode": 603, "message": "Incorrect Username Or Password"}), 401
            # --- !!! END CONDITIONAL PASSWORD CHECK !!! ---


            # --- Account Status Check ---
            if not user["Active"]:
                logger.warning(f"Login failed: Inactive account for username: {username}")
                return jsonify({"success": False, "message": "Account is inactive"}), 403

            # --- Application Access Check ---
            if user["Role"] != "SuperAdmin":
                allowed_apps = user.get("AllowedApps") or []
                app_name = config.get("APP_NAME", "UNKNOWN_APP")
                if app_name not in allowed_apps:
                    logger.warning(f"Login failed: User '{username}' not authorized for app '{app_name}'. Allowed: {allowed_apps}")
                    return jsonify({"success": False, "message": f"You Are Not Authorized To Use The Application \"{app_name}\""}), 403

            # --- Two-Factor Authentication (2FA) Check ---
            if config.get("MBKAUTH_TWO_FA_ENABLE", False):
                two_fa_status = user.get("TwoFAStatus", False) # DB stores BOOLEAN
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
                        if not totp.verify(token_2fa):
                            logger.warning(f"Login failed: Invalid 2FA code for username: {username}")
                            return jsonify({"success": False, "message": "Invalid 2FA code"}), 401
                        logger.info(f"2FA verification successful for {username}")
                    except Exception as e:
                         logger.error(f"Error during 2FA verification for {username}: {e}")
                         return jsonify({"success": False, "message": "Error verifying 2FA code"}), 500
            # --- End 2FA Check ---


            # --- Login Success: Generate Session ---
            session_id = secrets.token_hex(32)
            logger.info(f"Generated session ID for username: {username}")

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

            logger.info(f"User '{username}' logged in successfully (Password Check Mode: {'Encrypted' if use_encryption else 'Plaintext'})")

            # Prepare response
            response_data = {
                "success": True,
                "message": "Login successful",
                "sessionId": session_id
            }
            resp = make_response(jsonify(response_data), 200)
            # Cookies are typically set by the after_request hook now
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


# --- Other Routes (/logout, /terminateAllSessions, /package, /version, /package-lock) ---
# Keep the rest of the routes from the previous version of routes.py here
# Ensure they also use `current_app.config["MBKAUTHE_CONFIG"]` where needed

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
@authenticate_token # Use the token authentication middleware
def terminate_all_sessions():
    # ... (terminateAllSessions logic as provided before) ...
    logger.warning("Received request to terminate all user sessions.")
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('UPDATE "Users" SET "SessionId" = NULL')
            users_updated = cur.rowcount
            logger.info(f"Cleared SessionId for {users_updated} users.")

            config = current_app.config["MBKAUTHE_CONFIG"] # Get config for session details
            session_table = config.get("SESSION_SQLALCHEMY_TABLE", "session")
            session_type = config.get("SESSION_TYPE")

            if session_type == "sqlalchemy":
                 # Use DELETE for safety unless TRUNCATE is explicitly desired and understood
                 cur.execute(f'DELETE FROM "{session_table}"')
                 # cur.execute(f'TRUNCATE TABLE "{session_table}" RESTART IDENTITY') # More aggressive
                 logger.info(f"Cleared session table '{session_table}'.")
            elif session_type == "filesystem":
                 session_dir = current_app.config.get("SESSION_FILE_DIR", os.path.join(os.getcwd(), 'flask_session'))
                 logger.warning(f"Terminating filesystem sessions - deleting files in {session_dir}")
                 try:
                      for filename in os.listdir(session_dir):
                           file_path = os.path.join(session_dir, filename)
                           if os.path.isfile(file_path):
                                os.unlink(file_path)
                      logger.info("Filesystem session files deleted.")
                 except Exception as fs_err:
                      logger.error(f"Error deleting filesystem session files: {fs_err}")
            else:
                 logger.warning(f"Session termination for backend type '{session_type}' needs specific implementation (e.g., Redis FLUSHDB/DEL).")

        conn.commit()
        session.clear() # Clear current request's session

        resp = make_response(jsonify({
            "success": True,
            "message": "All sessions terminated successfully"
        }), 200)
        cookie_options = get_cookie_options()
        resp.delete_cookie("sessionId", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        resp.delete_cookie("username", domain=cookie_options.get('domain'), path=cookie_options.get('path'))
        logger.warning("All user sessions terminated successfully.")
        return resp

    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error during terminateAllSessions: {e}", exc_info=True)
        if conn: conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error during session termination"}), 500
    finally:
        if conn: release_db_connection(conn)


# --- Informational Endpoints ---
@mbkauthe_bp.route("/package", methods=["GET"])
def package_info():
    # ... (package_info logic as provided before) ...
    try:
        metadata = importlib.metadata.metadata("mbkauthe")
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
    # ... (version_info logic as provided before) ...
    try:
        version = importlib.metadata.version("mbkauthepy")
        return jsonify({"version": version})
    except importlib.metadata.PackageNotFoundError:
        logger.error("Could not find version for 'mbkauthepy' package.")
        return jsonify({"success": False, "message": "Package 'mbkauthepy' not found"}), 404
    except Exception as e:
        logger.error(f"Error retrieving package version: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@mbkauthe_bp.route("/package-lock", methods=["GET"])
def package_lock_info():
    # ... (package_lock_info logic as provided before - prioritizing library deps) ...
    logger.info("Request for package-lock equivalent received.")
    try: # Prioritize library's own dependencies
        metadata = importlib.metadata.metadata("mbkauthepy")
        dependencies = metadata.get_all("Requires-Dist")
        return jsonify({
            "message": "Returning library's own dependencies",
            "name": metadata.get("Name"),
            "version": metadata.get("Version"),
            "dependencies": dependencies or []
        })
    except importlib.metadata.PackageNotFoundError:
         return jsonify({"success": False, "message": "Package 'mbkauthepy' not found"}), 404
    except Exception as e:
         logger.error(f"Error retrieving library dependencies: {e}")
         # Optionally fall through to try parsing project lock file, but often less useful
         return jsonify({"success": False, "message": "Could not determine project dependencies for mbkauthepy"}), 501