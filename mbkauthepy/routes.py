import logging
import os
import pybars
import secrets
import importlib.metadata
from pathlib import Path
from datetime import datetime, timedelta
import json

from flask import Blueprint, request, jsonify, session, render_template_string, current_app, redirect, url_for

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
from .utils import get_cookie_options, clear_auth_cookies

logger = logging.getLogger(__name__)

# Define the Blueprint
mbkauthe_bp = Blueprint('mbkauthe', __name__, url_prefix='/mbkauthe')

def get_template_path(template_name):
    """Get absolute path to template file with multiple fallback locations"""
    package_dir = Path(__file__).parent
    paths_to_try = [
        package_dir / 'templates' / template_name,
        Path.cwd() / 'templates' / template_name,
        Path.cwd() / 'mbkauthepy' / 'templates' / template_name
    ]

    for path in paths_to_try:
        if path.exists():
            return path

    logger.error(f"Template {template_name} not found in: {[str(p) for p in paths_to_try]}")
    return None

def render_handlebars_template(template_name, context):
    """Render a Handlebars template with the given context"""
    template_path = get_template_path(template_name)
    if not template_path:
        return "Template not found111111111111", 404

    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_source = f.read()

        compiler = Compiler()
        template = compiler.compile(template_source)
        rendered = template(context)
        return rendered
    except Exception as e:
        logger.error(f"Error rendering template {template_name}: {e}")
        return "Error rendering template", 500

@mbkauthe_bp.after_request
def after_request_callback(response):
    """Set cookies if user is in session"""
    if 'user' in session:
        user_info = session['user']
        cookie_opts = get_cookie_options()
        response.set_cookie("username", user_info.get('username', ''),
                           **{**cookie_opts, 'httponly': False})
        response.set_cookie("sessionId", user_info.get('sessionId', ''), **cookie_opts)
    return response

@mbkauthe_bp.route('/login')
def login_page():
    """
    Renders the login page using a Handlebars template with an absolute path.
    """
    try:
        config = current_app.config.get("MBKAUTHE_CONFIG", {})
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

        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(current_dir, 'templates', 'loginmbkauthe.handlebars')

        if not os.path.exists(template_path):
            logging.error(f"Template file does not exist at: {template_path}")
            return "Error: Login template not found.", 404

        compiler = pybars.Compiler()
        with open(template_path, "r", encoding="utf-8") as f:
            source = f.read()

        template = compiler.compile(source)
        html_output = template(context)

        return html_output

    except pybars._compiler.PybarsError as e:
        logging.error(f"Handlebars template syntax error in {template_path}: {e}")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                error_line = lines[min(len(lines), 882)] if len(lines) > 882 else ""
                logging.error(f"Line 883 content: {error_line.strip()}")
        except Exception as log_error:
            logging.error(f"Failed to read template for debugging: {log_error}")
        return "Error: Invalid Handlebars template syntax.", 400
    except FileNotFoundError:
        logging.error(f"Handlebars template not found. Looked for: {template_path}")
        return "Error: Login template not found.", 404
    except Exception as e:
        logging.error(f"Error rendering Handlebars template: {e}", exc_info=True)
        return "An internal error occurred.", 500

@mbkauthe_bp.route("/api/login", methods=["POST"])
def login():
    try:
        config = current_app.config["MBKAUTHE_CONFIG"]
    except KeyError:
        logger.error("MBKAUTHE_CONFIG not found in Flask app config.")
        return jsonify({"success": False, "message": "Server configuration error."}), 500

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token_2fa = data.get("token")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # User query with 2FA info
            user_query = """
                         SELECT u.id, \
                                u."UserName", \
                                u."Password", \
                                u."Role", \
                                u."Active", \
                                u."AllowedApps",
                                tfa."TwoFAStatus", \
                                tfa."TwoFASecret"
                         FROM "Users" u
                                  LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
                         WHERE u."UserName" = %s \
                         """
            cur.execute(user_query, (username,))
            user = cur.fetchone()

            if not user:
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401

            # Password verification
            if config.get("EncryptedPassword"):
                password_match = bcrypt.checkpw(password.encode('utf-8'),
                                               user["Password"].encode('utf-8'))
            else:
                password_match = (password == user["Password"])

            if not password_match:
                return jsonify({"success": False, "message": "Incorrect Username Or Password"}), 401

            if not user["Active"]:
                return jsonify({"success": False, "message": "Account is inactive"}), 403

            # App authorization check
            if user["Role"] != "SuperAdmin":
                allowed_apps = user.get("AllowedApps") or []
                app_name = config.get("APP_NAME", "UNKNOWN_APP")
                if not any(app.lower() == app_name.lower() for app in allowed_apps):
                    return jsonify({"success": False,
                                    "message": f"Not authorized for application {app_name}"}), 403

            # 2FA verification if enabled
            if config.get("MBKAUTH_TWO_FA_ENABLE") and user.get("TwoFAStatus"):
                if not token_2fa:
                    return jsonify({"success": False, "twoFactorRequired": True}), 200

                if not pyotp.TOTP(user["TwoFASecret"]).verify(token_2fa, valid_window=1):
                    return jsonify({"success": False, "message": "Invalid 2FA code"}), 401

            # Create new session
            session_id = secrets.token_hex(32)
            sid = secrets.token_urlsafe(24)  # Generate unique sid for session table
            csrf_secret = secrets.token_hex(16)
            session_expiry = config.get("SESSION_PERMANENT_MAX_AGE", 172800000) / 1000  # Convert ms to seconds
            expires_at = datetime.now() + timedelta(seconds=session_expiry)

            # Construct sess JSON object
            cookie_opts = get_cookie_options()
            cookie_opts['originalMaxAge'] = int(session_expiry * 1000)  # Convert back to ms
            cookie_opts['expires'] = expires_at.isoformat() + 'Z'
            sess_data = {
                'cookie': cookie_opts,
                'csrfSecret': csrf_secret,
                'user': {
                    'id': user['id'],
                    'username': user['UserName'],
                    'role': user['Role'],
                    'sessionId': session_id
                }
            }

            # Update Users table
            cur.execute('UPDATE "Users" SET "SessionId" = %s WHERE "UserName" = %s',
                        (session_id, user['UserName']))
            # Insert into session table
            cur.execute(
                """
                INSERT INTO "session" (sid, sess, expire, username)
                VALUES (%s, %s, %s, %s)
                """,
                (sid, json.dumps(sess_data), expires_at, user['UserName'])
            )

            session.clear()
            session['user'] = {
                'id': user['id'],
                'username': user['UserName'],
                'role': user['Role'],
                'sessionId': session_id
            }
            session.permanent = True
            conn.commit()

            response = jsonify({
                "success": True,
                "message": "Login successful",
                "sessionId": session_id
            })
            response.set_cookie("sessionId", session_id, **get_cookie_options())
            response.set_cookie("mbkauthe.sid", sid, **get_cookie_options())  # Set sid cookie
            return response

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)

@mbkauthe_bp.route("/2fa")
def two_fa_page():
    """Render 2FA verification page"""
    if 'pre_auth_user' not in session:
        return redirect(url_for('mbkauthe.login_page'))

    context = {
        'layout': False,
        'customURL': current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home')
    }

    rendered = render_handlebars_template('2fa.handlebars', context)
    return rendered if rendered else "Error loading template", 500

@mbkauthe_bp.route("/api/logout", methods=["POST"])
@validate_session
def logout():
    conn = None
    try:
        user_info = session.get('user', {})
        if user_info.get('id'):
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute('UPDATE "Users" SET "SessionId" = NULL WHERE "id" = %s',
                            (user_info['id'],))
                cur.execute('DELETE FROM "session" WHERE sess->\'user\'->>\'sessionId\' = %s',
                            (user_info['sessionId'],))
            conn.commit()

        session.clear()
        response = jsonify({"success": True, "message": "Logout successful"})
        clear_auth_cookies(response)
        return response

    except Exception as e:
        logger.error(f"Logout error: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
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
            cur.execute('DELETE FROM "session"')
        conn.commit()

        session.clear()
        response = jsonify({"success": True, "message": "All sessions terminated"})
        clear_auth_cookies(response)
        return response

    except Exception as e:
        logger.error(f"Session termination error: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "Internal Server Error"}), 500
    finally:
        if conn:
            release_db_connection(conn)

def get_error_context(code, error, message, pagename, page, details=None):
    """Create context for error template"""
    return {
        'layout': False,
        'code': code,
        'error': error,
        'message': message,
        'pagename': pagename,
        'page': page,
        'details': details,
        'version': importlib.metadata.version("mbkauthepy") if importlib.metadata else "N/A"
    }

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
        "COOKIE_EXPIRE_TIME": f"{config.get('COOKIE_EXPIRE_TIME', 'N/A')}",
        "IS_DEPLOYED": config.get("IS_DEPLOYED", False),
        "DOMAIN": config.get("DOMAIN", "N/A"),
        "loginRedirectURL": config.get("loginRedirectURL", "N/A"),
        "GITHUB_LOGIN_ENABLED": config.get("GITHUB_LOGIN_ENABLED", False)
    }

    template = """
<html>
<head>
    <title>Version and Configuration Information</title>
    <link rel="icon" type="image/x-icon" href="https://mbktechstudio.com/Assets/Images/Icon/dgicon.svg">
    <style>
        :root {
            --bg-color: #121212;
            --card-bg: #1e1e1e;
            --text-color: #e0e0e0;
            --text-secondary: #a0a0a0;
            --primary: #bb86fc;
            --primary-dark: #3700b3;
            --secondary: #03dac6;
            --border-color: #333;
            --success: #4caf50;
            --warning: #ff9800;
            --error: #f44336;
            --key-color: #bb86fc;
            --string-color: #03dac6;
            --number-color: #ff7043;
            --boolean-color: #7986cb;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--bg-color);
            color: var(--text-color);
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }

        h1 {
            color: var(--primary);
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
            font-weight: bold;
            letter-spacing: 1px;
        }

        .info-section {
            margin-bottom: 25px;
            padding: 20px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background-color: rgba(30, 30, 30, 0.7);
            transition: all 0.3s ease;
        }

        .info-section:hover {
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(187, 134, 252, 0.3);
        }

        .info-section h2 {
            color: var(--primary);
            border-bottom: 2px solid var(--primary-dark);
            padding-bottom: 8px;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 1.2em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .info-row {
            display: flex;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }

        .info-label {
            font-weight: 600;
            color: var(--text-secondary);
            min-width: 220px;
            font-size: 0.95em;
        }

        .info-value {
            flex: 1;
            word-break: break-word;
            color: var(--text-color);
        }

        .version-status {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            margin-left: 10px;
        }

        .version-up-to-date {
            background: rgba(76, 175, 80, 0.2);
            color: var(--success);
            border: 1px solid var(--success);
        }

        .version-outdated {
            background: rgba(244, 67, 54, 0.2);
            color: var(--error);
            border: 1px solid var(--error);
        }

        .version-fetch-error {
            background: rgba(255, 152, 0, 0.2);
            color: var(--warning);
            border: 1px solid var(--warning);
        }

        .json-container {
            background: #252525;
            border-radius: 8px;
            padding: 15px;
            max-height: 400px;
            overflow: auto;
            white-space: pre;
            font-family: 'Fira Code', monospace;
            font-size: 0.9em;
            color: var(--text-color);
            border: 1px solid var(--border-color);
            position: relative;
            animation: fadeIn 0.5s ease-in;
            transition: box-shadow 0.3s ease;
        }

        .json-container:hover {
            box-shadow: 0 0 15px rgba(187, 134, 252, 0.4);
        }

        .json-container pre {
            margin: 0;
        }

        .json-container .json-key {
            color: var(--key-color);
        }

        .json-container .json-string {
            color: var(--string-color);
        }

        .json-container .json-number {
            color: var(--number-color);
        }

        .json-container .json-boolean {
            color: var(--boolean-color);
        }

        .json-copy-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: var(--primary);
            color: var(--text-color);
            border: none;
            border-radius: 4px;
            padding: 5px 10px;
            cursor: pointer;
            font-size: 0.8em;
            transition: background 0.3s ease;
        }

        .json-copy-button:hover {
            background: var(--primary-dark);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #2d2d2d;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb {
            background: #555;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary);
        }

        .tooltip {
            position: relative;
            display: inline-block;
        }

        .tooltip .tooltiptext {
            visibility: hidden;
            width: 120px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -60px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.8em;
        }

        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Version and Configuration Dashboard</h1>
        <div class="info-section">
            <h2>Version Information</h2>
            <div class="info-row">
                <div class="info-label">Current Version:</div>
                <div class="info-value" id="CurrentVersion">{{ current_version }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Latest Version:</div>
                <div class="info-value">
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
                    <div class="info-value">{{ value }}</div>
                </div>
            {% endfor %}
        </div>
        <div class="info-section">
            <h2>Package Information</h2>
            <div class="json-container">
                <button class="json-copy-button tooltip" onclick="copyJson()">Copy JSON<span class="tooltiptext">Copy to Clipboard</span></button>
                <pre id="json-content">{{ package_json | tojson(indent=2) }}</pre>
            </div>
        </div>
    </div>
    <script>
        function copyJson() {
            const jsonText = document.getElementById('json-content').textContent;
            navigator.clipboard.writeText(jsonText).then(() => {
                const button = document.querySelector('.json-copy-button');
                button.textContent = 'Copied!';
                button.style.background = 'var(--success)';
                setTimeout(() => {
                    button.textContent = 'Copy JSON';
                    button.style.background = 'var(--primary)';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy JSON:', err);
            });
        }

        // Basic JSON syntax highlighting
        document.addEventListener('DOMContentLoaded', () => {
            const jsonElement = document.getElementById('json-content');
            let jsonText = jsonElement.innerHTML;
            jsonText = jsonText.replace(/"([^"]+)":/g, '<span class="json-key">"$1":</span>');
            jsonText = jsonText.replace(/"([^"]+)"/g, '<span class="json-string">"$1"</span>');
            jsonText = jsonText.replace(/\b(\d+)\b/g, '<span class="json-number">$1</span>');
            jsonText = jsonText.replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>');
            jsonElement.innerHTML = jsonText;
        });
    </script>
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
@mbkauthe_bp.app_errorhandler(401)
def unauthorized_error(error):
    """Handle 401 errors with custom template"""
    context = get_error_context(
        401, "Unauthorized",
        "You need to login to access this page.",
        "Login",
        url_for('mbkauthe.login_page')
    )
    rendered = render_handlebars_template('Error.handlebars', context)
    if isinstance(rendered, tuple):
        return rendered
    return rendered, 401

@mbkauthe_bp.app_errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors with custom template"""
    context = get_error_context(
        403, "Forbidden",
        "You don't have permission to access this resource.",
        "Home",
        current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home')
    )
    rendered = render_handlebars_template('Error.handlebars', context)
    if isinstance(rendered, tuple):
        return rendered
    return rendered, 403

@mbkauthe_bp.app_errorhandler(404)
def not_found_error(error):
    """Handle 404 errors with custom template"""
    context = get_error_context(
        404, "Not Found",
        "The requested page could not be found.",
        "Home",
        current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home')
    )
    rendered = render_handlebars_template('Error.handlebars', context)
    if isinstance(rendered, tuple):
        return rendered
    return rendered, 404

@mbkauthe_bp.app_errorhandler(500)
def internal_server_error(error):
    """Handle 500 errors with custom template"""
    logger.error(f"Caught an unhandled exception: {error}", exc_info=True)
    original_exception = getattr(error, 'original_exception', error)

    context = get_error_context(
        500, "Internal Server Error",
        "An unexpected error occurred. Our team has been notified.",
        "Home",
        current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home'),
        details=str(original_exception)
    )
    rendered = render_handlebars_template('Error.handlebars', context)
    if isinstance(rendered, tuple):
        return rendered
    return rendered, 500
