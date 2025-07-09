# mbkauthepy/routes.py

import logging
import os
import json
import secrets
import importlib.metadata

# Flask and related imports
from flask import Blueprint, request, jsonify, session, make_response, current_app,render_template
from markupsafe import Markup  # Corrected import for Markup

# Database and Authentication imports
import psycopg2
import psycopg2.extras
import bcrypt
import requests
import pyotp

# Handlebars template engine import
from pybars import Compiler

# Local module imports
from .db import get_db_connection, release_db_connection
from .middleware import authenticate_token, validate_session
from .utils import get_cookie_options

logger = logging.getLogger(__name__)

# Define the Blueprint. The template_folder argument is important for Flask to know
# where to look, even though we are constructing an absolute path manually.
mbkauthe_bp = Blueprint('mbkauthe', __name__, url_prefix='/mbkauthe', template_folder='templates')


@mbkauthe_bp.after_request
def after_request_callback(response):
    """This hook runs after each request to set cookies if a user is in the session."""
    if 'user' in session and session.get('user'):
        user_info = session['user']
        try:
            cookie_opts_no_http = get_cookie_options(http_only=False)
            cookie_opts_http = get_cookie_options(http_only=True)
            response.set_cookie("username", user_info.get('username', ''), **cookie_opts_no_http)
            response.set_cookie("sessionId", user_info.get('sessionId', ''), **cookie_opts_http)
        except NameError:
            logger.error("get_cookie_options function not found or not imported correctly.")
        except Exception as e:
            logger.error(f"Error setting cookies in after_request: {e}")
    return response


import os
from pathlib import Path
import importlib.metadata
from flask import current_app, session


def render_handlebars(template, context, partials=None):
    """Render a Handlebars template with the given context and partials.

    Args:
        template: Path to the Handlebars template file
        context: Dictionary with template variables
        partials: Optional dictionary of partial templates

    Returns:
        tuple: (rendered_template, status_code)
    """
    try:
        template_path = Path(template)
        if not template_path.is_file():
            raise FileNotFoundError(f"Template file not found: {template_path}")

        # Read main template
        with open(template_path, 'r', encoding='utf-8') as template_file:
            main_template_source = template_file.read()

        # Initialize compiler
        compiler = Compiler()

        # Register partials if provided
        if partials:
            for name, partial_path in partials.items():
                partial_path = Path(partial_path)
                if partial_path.is_file():
                    with open(partial_path, 'r', encoding='utf-8') as partial_file:
                        compiler.register_partial(name, partial_file.read())

        # Compile and render
        compiled_template = compiler.compile(main_template_source)
        rendered = compiled_template(context, helpers=None)
        return rendered, 200

    except FileNotFoundError as e:
        current_app.logger.error(f"Template file error: {str(e)}")
        return "Template not found.", 404
    except Exception as e:
        current_app.logger.error(f"Error rendering Handlebars template: {str(e)}", exc_info=True)
        return "An internal error occurred.", 500


@mbkauthe_bp.route('/login')
def login_page():
    """Render the login page using a Handlebars template."""
    config = current_app.config.get("MBKAUTHE_CONFIG", {})

    # Get package version
    try:
        version = importlib.metadata.version("mbkauthepy")
    except importlib.metadata.PackageNotFoundError:
        version = "N/A"

    user = session.get('user')
    context = {
        'layout': False,
        'customURL': config.get('loginRedirectURL', '/home'),
        'userLoggedIn': bool(user),
        'username': user.get('username', '') if user else '',
        'version': version,
        'appName': config.get('APP_NAME', 'APP').upper()
    }

    # Get template path - works whether installed or in development
    try:
        # Try package-relative path first
        import mbkauthepy
        package_dir = Path(mbkauthepy.__file__).parent
        template_path = package_dir / 'templates' / 'loginmbkauthe.handlebars'
    except ImportError:
        # Fallback to absolute path (development)
        pass

    response, status = render_handlebars(template_path, context)
    return response, status


@mbkauthe_bp.route("/api/login", methods=["POST"])
def login():
    try:
        config = current_app.config["MBKAUTHE_CONFIG"]
    except KeyError:
        logger.error("MBKAUTHE_CONFIG not found in Flask app config.")
        return jsonify({"success": False, "message": "Server configuration error."}), 500

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request body (expecting JSON)"}), 400

    username = data.get("username")
    password = data.get("password")
    token_2fa = data.get("token")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
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

            use_encryption = config.get("EncryptedPassword", False)
            password_match = False

            if use_encryption:
                try:
                    password_bytes = password.encode('utf-8')
                    stored_hash_bytes = user["Password"].encode('utf-8') if isinstance(user["Password"], str) else user[
                        "Password"]
                    password_match = bcrypt.checkpw(password_bytes, stored_hash_bytes)
                except Exception as e:
                    logger.error(f"Bcrypt error for {username}: {e}")
                    return jsonify({"success": False, "errorCode": 605, "message": "Internal Server Error"}), 500
            else:
                password_match = (password == user["Password"])

            if not password_match:
                logger.warning(f"Login failed: Incorrect password for username: {username}")
                return jsonify({"success": False, "errorCode": 603, "message": "Incorrect Username Or Password"}), 401

            logger.info("Password matches!")

            if not user["Active"]:
                logger.warning(f"Login failed: Inactive account for username: {username}")
                return jsonify({"success": False, "message": "Account is inactive"}), 403

            if user["Role"] != "SuperAdmin":
                allowed_apps = user.get("AllowedApps") or []
                app_name = config.get("APP_NAME", "UNKNOWN_APP")
                if not any(app.lower() == app_name.lower() for app in allowed_apps):
                    logger.warning(f"User '{username}' not authorized for app '{app_name}'.")
                    return jsonify({"success": False,
                                    "message": f"You Are Not Authorized To Use The Application \"{app_name}\""}), 403

            if config.get("MBKAUTH_TWO_FA_ENABLE", False):
                if user.get("TwoFAStatus"):
                    if not token_2fa:
                        logger.warning(f"2FA code required but not provided for {username}")
                        return jsonify({"success": False, "message": "Please Enter 2FA code"}), 401

                    two_fa_secret = user.get("TwoFASecret")
                    if not two_fa_secret:
                        logger.error(f"2FA enabled for {username} but no secret is stored.")
                        return jsonify({"success": False, "message": "2FA configuration error"}), 500

                    totp = pyotp.TOTP(two_fa_secret)
                    if not totp.verify(token_2fa, valid_window=1):
                        logger.warning(f"Invalid 2FA code for username: {username}")
                        return jsonify({"success": False, "message": "Invalid 2FA code"}), 401

            session_id = secrets.token_hex(32)
            logger.info(f"Generated session ID for username: {username}")

            # Update user session in database
            update_query = 'UPDATE "Users" SET "SessionId" = %s WHERE "UserName" = %s'
            cur.execute(update_query, (session_id, user['UserName']))

            session.clear()
            session['user'] = {
                'id': user['id'],
                'username': user['UserName'],
                'role': user['Role'],
                'sessionId': session_id
            }
            session.permanent = True

            conn.commit()
            logger.info(f"User '{username}' logged in successfully")

            # Create response with session cookie
            response = jsonify({
                "success": True,
                "message": "Login successful",
                "sessionId": session_id
            })

            # Set cookie with proper options
            cookie_options = {
                'key': 'sessionId',
                'value': session_id,
                'max_age': 86400 * 30,  # 30 days
                'secure': True,
                'httponly': True,
                'samesite': 'Lax'
            }

            # Only set samesite=None if using HTTPS
            if request.is_secure:
                cookie_options['samesite'] = 'None'

            response.set_cookie(**cookie_options)

            return response, 200

    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error during login for {username}: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)


@mbkauthe_bp.route("/api/logout", methods=["POST"])
@validate_session
def logout():
    conn = None
    try:
        user_info = session.get('user', {})
        username = user_info.get('username', 'unknown')
        user_id = user_info.get('id')

        # Initialize response
        resp = make_response(jsonify({
            "success": True,
            "message": "Logout successful"
        }), 200)

        # Clear Flask session
        session.clear()

        # Update database
        if user_id:
            try:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute(
                        'UPDATE "Users" SET "SessionId" = NULL WHERE "id" = %s',
                        (user_id,)
                    )
                conn.commit()
            except psycopg2.Error as e:
                logger.error(f"Database error during logout for {username}: {e}")
                if conn:
                    conn.rollback()

        # Get domain from config if exists
        domain = current_app.config.get('MBKAUTHE_CONFIG', {}).get('DOMAIN')

        # Clear cookies properly
        cookies_to_clear = [
            "sessionId",
            "username",
            current_app.config.get('SESSION_COOKIE_NAME', 'session')
        ]

        for cookie_name in cookies_to_clear:
            if domain:
                resp.delete_cookie(
                    cookie_name,
                    path='/',
                    domain=domain
                )
            else:
                resp.delete_cookie(
                    cookie_name,
                    path='/'
                )

        logger.info(f"Successful logout for user: {username}")
        return resp

    except Exception as e:
        logger.critical(f"Critical error during logout: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Internal Server Error"
        }), 500
    finally:
        if conn:
            release_db_connection(conn)

@mbkauthe_bp.route("/api/terminateAllSessions", methods=["POST"])
@authenticate_token
def terminate_all_sessions():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('UPDATE "Users" SET "SessionId" = NULL')
            cur.execute('DELETE FROM "session"')  # Assuming a 'session' table exists
        conn.commit()

        session.clear()

        resp = make_response(jsonify({"success": True, "message": "All sessions terminated successfully"}), 200)
        cookie_options = get_cookie_options()
        domain = cookie_options.get('domain')
        path = cookie_options.get('path', '/')
        resp.delete_cookie("sessionId", domain=domain, path=path)
        resp.delete_cookie("username", domain=domain, path=path)
        resp.delete_cookie(current_app.config.get('SESSION_COOKIE_NAME', 'session'), domain=domain, path=path)

        logger.info("All user sessions terminated successfully.")
        return resp
    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error terminating sessions: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)


def get_latest_version_from_pypi(package_name):
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
        response.raise_for_status()
        return response.json()["info"]["version"]
    except requests.RequestException as e:
        logger.error(f"Failed to fetch latest version from PyPI: {e}")
        return None


@mbkauthe_bp.route("/info", methods=["GET"])
@mbkauthe_bp.route("/i", methods=["GET"])
def mbkauthe_info():
    # Note: This route still uses render_template_string, which is fine.
    # It does not need to be converted to Handlebars unless you want to.
    package_name = "mbkauthepy"
    config = current_app.config.get("MBKAUTHE_CONFIG", {})

    try:
        current_version = importlib.metadata.version(package_name)
        metadata = importlib.metadata.metadata(package_name)
        package_json = {k: v for k, v in metadata.items()}
    except importlib.metadata.PackageNotFoundError:
        current_version = "Unknown"
        package_json = {"error": f"Package '{package_name}' not found."}

    latest_version = get_latest_version_from_pypi(package_name)

    info_data = {
        "APP_NAME": config.get("APP_NAME", "N/A"),
        "MBKAUTH_TWO_FA_ENABLE": config.get("MBKAUTH_TWO_FA_ENABLE", False),
        "COOKIE_EXPIRE_TIME": f"{config.get('COOKIE_EXPIRE_TIME', 'N/A')} Days",
        "IS_DEPLOYED": config.get("IS_DEPLOYED", False),
        "DOMAIN": config.get("DOMAIN", "N/A"),
        "Login Redirect URL": config.get("loginRedirectURL", "N/A")
    }

    # Using render_template_string is okay for simple, internal pages like this.
    from flask import render_template_string
    template = """
    <html>
    <head>
      <title>Version and Configuration Information</title>
      <style>
        body { font-family: sans-serif; background-color: #121212; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1000px; margin: auto; background: #1e1e1e; padding: 20px; border-radius: 8px; }
        h1, h2 { color: #bb86fc; }
        .info-section { margin-bottom: 25px; padding: 15px; border: 1px solid #333; border-radius: 5px; }
        .info-row { display: flex; padding: 5px 0; }
        .info-label { font-weight: bold; color: #a0a0a0; min-width: 220px; }
        .json-container { background: #252525; border-radius: 5px; padding: 10px; max-height: 400px; overflow: auto; white-space: pre; font-family: monospace; }
        .version-status { margin-left: 10px; padding: 3px 8px; border-radius: 12px; font-size: 0.9em; }
        .version-up-to-date { background: #4caf50; color: white; }
        .version-outdated { background: #f44336; color: white; }
        .version-fetch-error { background: #ff9800; color: black; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Version and Configuration Dashboard</h1>
        <div class="info-section">
          <h2>Version Information</h2>
          <div class="info-row">
            <div class="info-label">Current Version:</div>
            <div>{{ current_version }}</div>
          </div>
          <div class="info-row">
            <div class="info-label">Latest Version:</div>
            <div>
              {{ latest_version or 'Could not fetch latest version' }}
              {% if latest_version %}
                {% if current_version == latest_version %}
                  <span class="version-status version-up-to-date">Up to date</span>
                {% else %}
                  <span class="version-status version-outdated">Update available</span>
                {% endif %}
              {% else %}
                <span class="version-status version-fetch-error">Fetch error</span>
              {% endif %}
            </div>
          </div>
        </div>
        <div class="info-section">
          <h2>Configuration Information</h2>
          {% for key, value in info_data.items() %}
          <div class="info-row">
            <div class="info-label">{{ key }}:</div>
            <div>{{ value }}</div>
          </div>
          {% endfor %}
        </div>
        <div class="info-section">
          <h2>Package Information</h2>
          <div class="json-container">{{ package_json | tojson(indent=2) }}</div>
        </div>
      </div>
    </body>
    </html>
    """

    return render_template_string(
        template,
        current_version=current_version,
        latest_version=latest_version,
        info_data=info_data,
        package_json=package_json
    )

