# mbkauthepy/middleware.py

import logging
from functools import wraps
from flask import session, request, current_app, abort
from werkzeug.exceptions import HTTPException
import psycopg2
import psycopg2.extras
from .db import get_db_connection, release_db_connection

logger = logging.getLogger(__name__)

def _restore_session_from_cookie():
    """
    Attempt to restore a user session from the 'sessionId' cookie.
    This is called if a request arrives without a server-side session but with a cookie.
    Returns True on success, False on failure.
    """
    if 'user' not in session and 'sessionId' in request.cookies:
        session_id = request.cookies.get('sessionId')
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = 'SELECT id, "UserName", "Role", "SessionId" FROM "Users" WHERE "SessionId" = %s AND "Active" = TRUE'
                cur.execute(query, (session_id,))
                user = cur.fetchone()

                if user:
                    session.clear()
                    session['user'] = {
                        'id': user['id'],
                        'username': user['UserName'],
                        'role': user['Role'],
                        'sessionId': user['SessionId']
                    }
                    session.permanent = True
                    logger.info(f"Restored session from cookie for user: {user['UserName']}")
                    return True
        except Exception as e:
            logger.error(f"Error during session restoration from cookie: {e}", exc_info=True)
        finally:
            if conn:
                release_db_connection(conn)
    return False

def validate_session(f):
    """
    Decorator to validate the user's session against the database.
    This decorator does not take arguments.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config.get("MBKAUTHE_CONFIG", {})
        if 'user' not in session and not _restore_session_from_cookie():
            abort(401, "Authentication required. Please log in to continue.")
        user_session = session['user']
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = 'SELECT "SessionId", "Active", "Role", "AllowedApps" FROM "Users" WHERE "id" = %s'
                cur.execute(query, (user_session['id'],))
                user_db = cur.fetchone()
                if not user_db or user_db['SessionId'] != user_session['sessionId']:
                    session.clear()
                    abort(401, "Your session has expired or is invalid. Please log in again.")
                if not user_db['Active']:
                    session.clear()
                    abort(403, "Your account is currently inactive. Please contact an administrator.")
                if user_db['Role'] != "SuperAdmin":
                    allowed_apps = user_db.get('AllowedApps') or []
                    app_name = config.get("APP_NAME")
                    if not app_name or app_name.lower() not in [app.lower() for app in allowed_apps]:
                        abort(403, f"Access denied. You are not authorized for the '{app_name or 'Unknown App'}' application.")
                return f(*args, **kwargs)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during session validation for user '{user_session.get('username')}': {e}", exc_info=True)
            abort(500, "An internal server error occurred while validating your session.")
        finally:
            if conn:
                release_db_connection(conn)
    return decorated_function

def check_role_permission(required_role):
    """
    Decorator factory to check if the user has the required role.
    This decorator takes an argument.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                abort(401, "Authentication is required to check role permissions.")
            user_role = session['user'].get('role')
            if required_role.lower() != "any" and user_role != required_role:
                logger.warning(
                    f"Role permission denied for user '{session['user']['username']}'. "
                    f"Required: '{required_role}', Has: '{user_role}'."
                )
                abort(403, f"Access denied. This action requires the '{required_role}' role.")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_session_and_role(required_role):
    """
    Decorator factory that chains session validation and role checking.
    This decorator takes an argument.
    """
    def decorator(f):
        # Apply decorators from the inside out.
        # 1. check_role_permission is applied to the original function `f`.
        # 2. validate_session is applied to the result of that.
        return validate_session(check_role_permission(required_role)(f))
    return decorator

def authenticate_token(f):
    """
    Decorator to authenticate API requests using a static token.
    This decorator does not take arguments.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config.get("MBKAUTHE_CONFIG", {})
        provided_token = request.headers.get("Authorization", "")
        expected_token = config.get("Main_SECRET_TOKEN")
        if not expected_token:
             logger.error("CRITICAL: Main_SECRET_TOKEN is not configured.")
             abort(500, "Server authentication is not configured correctly.")
        if provided_token.startswith("Bearer "):
            provided_token = provided_token.split(" ", 1)[1]
        if not provided_token or provided_token != expected_token:
            logger.warning("API token authentication failed.")
            abort(401, "Invalid or missing API authentication token.")
        return f(*args, **kwargs)
    return decorated_function