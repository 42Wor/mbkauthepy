# mbkauthepy/routes.py

import logging
import os
import json
import secrets
import importlib.metadata
from pathlib import Path

# Flask and related imports
from flask import Blueprint, request, jsonify, session, make_response, current_app, redirect, url_for
from markupsafe import Markup

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
from .utils import get_cookie_options, clear_auth_cookies

logger = logging.getLogger(__name__)

# Define the Blueprint
mbkauthe_bp = Blueprint('mbkauthe', __name__, url_prefix='/mbkauthe')


def get_template_path(template_name):
    """Get absolute path to Handlebars template file"""
    try:
        # Try package-relative path first
        package_dir = Path(__file__).parent.parent
        template_path = package_dir / 'templates' / template_name
        if template_path.exists():
            return template_path

        # Fallback to absolute path (development)
        template_path = Path.cwd() / 'templates' / template_name
        return template_path if template_path.exists() else None
    except Exception as e:
        logger.error(f"Error locating template {template_name}: {e}")
        return None


def render_handlebars_template(template_name, context):
    """Render a Handlebars template with the given context"""
    template_path = get_template_path(template_name)
    if not template_path:
        return "Template not found", 404

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
                            **{**cookie_opts, 'http_only': False})
        response.set_cookie("sessionId", user_info.get('sessionId', ''), **cookie_opts)
    return response


from pathlib import Path
import os


def get_template_path(template_name):
    """Get absolute path to template file with multiple fallback locations"""
    # Try package installation path first
    package_dir = Path(__file__).parent.parent
    paths_to_try = [
        package_dir / 'templates' / template_name,  # Installed package location
        Path.cwd() / 'templates' / template_name,  # Development location
        Path.cwd() / 'mbkauthepy' / 'templates' / template_name  # Alternative dev location
    ]

    for path in paths_to_try:
        if path.exists():
            return path

    logger.error(f"Template {template_name} not found in: {[str(p) for p in paths_to_try]}")
    return None


@mbkauthe_bp.route('/login')
def login_page():
    """Render the login page"""
    config = current_app.config.get("MBKAUTHE_CONFIG", {})
    try:
        version = importlib.metadata.version("mbkauthepy")
    except importlib.metadata.PackageNotFoundError:
        version = "N/A"

    context = {
        'layout': False,
        'customURL': config.get('loginRedirectURL', '/home'),
        'userLoggedIn': 'user' in session,
        'username': session.get('user', {}).get('username', ''),
        'version': version,
        'appName': config.get('APP_NAME', 'APP').upper()
    }

    template_path = get_template_path('loginmbkauthe.handlebars')
    if not template_path:
        logger.error("Login template not found at any location")
        return "Login page temporarily unavailable", 500

    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_source = f.read()

        compiler = Compiler()
        template = compiler.compile(template_source)
        rendered = template(context)

        response = make_response(rendered)
        return response

    except Exception as e:
        logger.error(f"Error rendering login template: {str(e)}", exc_info=True)
        return "Error loading login page", 500

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
            cur.execute('UPDATE "Users" SET "SessionId" = %s WHERE "UserName" = %s',
                        (session_id, user['UserName']))

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


@mbkauthe_bp.route("/info")
@mbkauthe_bp.route("/i")
def info_page():
    """Render system information page"""
    config = current_app.config.get("MBKAUTHE_CONFIG", {})
    version = importlib.metadata.version("mbkauthepy") if importlib.metadata else "N/A"

    try:
        latest_version = requests.get(
            "https://pypi.org/pypi/mbkauthepy/json", timeout=5
        ).json()["info"]["version"]
    except Exception:
        latest_version = "Unknown"

    context = {
        'layout': False,
        'mbkautheVar': config,
        'version': version,
        'latestVersion': latest_version
    }

    rendered = render_handlebars_template('info.handlebars', context)
    return rendered if rendered else "Error loading template", 500


@mbkauthe_bp.app_errorhandler(401)
def unauthorized_error(error):
    """Handle 401 errors with custom template"""
    context = get_error_context(
        401, "Unauthorized",
        "You need to login to access this page.",
        "Login",
        url_for('mbkauthe.login_page')
    )
    rendered = render_handlebars_template('error.handlebars', context)
    return rendered if rendered else str(error), 401


@mbkauthe_bp.app_errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors with custom template"""
    context = get_error_context(
        403, "Forbidden",
        "You don't have permission to access this resource.",
        "Home",
        current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home')
    )
    rendered = render_handlebars_template('error.handlebars', context)
    return rendered if rendered else str(error), 403


@mbkauthe_bp.app_errorhandler(404)
def not_found_error(error):
    """Handle 404 errors with custom template"""
    context = get_error_context(
        404, "Not Found",
        "The requested page could not be found.",
        "Home",
        current_app.config.get("MBKAUTHE_CONFIG", {}).get('loginRedirectURL', '/home')
    )
    rendered = render_handlebars_template('error.handlebars', context)
    return rendered if rendered else str(error), 404