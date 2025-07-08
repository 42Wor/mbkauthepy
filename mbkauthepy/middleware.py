import logging
from functools import wraps
from flask import session, request, make_response, render_template, current_app
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from .db import get_db_connection, release_db_connection
from .utils import get_cookie_options

logger = logging.getLogger(__name__)


# --- Session Management ---
def _restore_session_from_cookie():
    """Attempt to restore session from sessionId cookie"""
    if 'user' not in session and 'sessionId' in request.cookies:
        session_id = request.cookies.get('sessionId')
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = """
                    SELECT id, "UserName", "Role", "SessionId", "Active", "AllowedApps"
                    FROM "Users" 
                    WHERE "SessionId" = %s
                """
                cur.execute(query, (session_id,))
                user = cur.fetchone()

                if user:
                    session['user'] = {
                        'id': user['id'],
                        'username': user['UserName'],
                        'role': user['Role'],
                        'sessionId': user['SessionId']
                    }
                    logger.info(f"Restored session for {user['UserName']}")
                    return True
        except Exception as e:
            logger.error(f"Session restoration error: {e}")
        finally:
            if conn:
                release_db_connection(conn)
    return False


# --- Decorators ---
def validate_session(f):
    """Validate user session against database"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config["MBKAUTHE_CONFIG"]

        # Try to restore session if not present
        if 'user' not in session and not _restore_session_from_cookie():
            return render_template("Error/NotLoggedIn.html"), 401

        user_session = session['user']
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = """
                    SELECT "SessionId", "Active", "Role", "AllowedApps"
                    FROM "Users"
                    WHERE "id" = %s
                """
                cur.execute(query, (user_session['id'],))
                user_db = cur.fetchone()

                if not user_db or user_db['SessionId'] != user_session['sessionId']:
                    session.clear()
                    resp = make_response(render_template("Error/SessionExpire.html"))
                    # Fix: Use proper cookie deletion
                    resp.delete_cookie('sessionId', path='/')
                    if current_app.config.get('MBKAUTHE_CONFIG', {}).get('DOMAIN'):
                        resp.delete_cookie('sessionId',
                                         path='/',
                                         domain=current_app.config['MBKAUTHE_CONFIG']['DOMAIN'])
                    return resp, 401

                if not user_db['Active']:
                    session.clear()
                    resp = make_response(render_template("Error/AccountInactive.html"))
                    # Same fix for inactive account case
                    resp.delete_cookie('sessionId', path='/')
                    if current_app.config.get('MBKAUTHE_CONFIG', {}).get('DOMAIN'):
                        resp.delete_cookie('sessionId',
                                         path='/',
                                         domain=current_app.config['MBKAUTHE_CONFIG']['DOMAIN'])
                    return resp, 403

                if user_db['Role'] != "SuperAdmin":
                    allowed_apps = user_db['AllowedApps'] or []
                    if config["APP_NAME"] not in [app.lower() for app in allowed_apps]:
                        session.clear()
                        resp = make_response(render_template(
                            "Error/AccessDenied.html",
                            message=f"Not authorized for {config['APP_NAME']}"
                        ))
                        resp.delete_cookie('sessionId', **get_cookie_options())
                        return resp, 403

                return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return render_template("Error/InternalError.html"), 500
        finally:
            if conn:
                release_db_connection(conn)

    return decorated_function


def check_role_permission(required_role):
    """Check if user has required role"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return render_template("Error/NotLoggedIn.html"), 401

            user_role = session['user'].get('role')

            if required_role.lower() == "any" or user_role == required_role:
                return f(*args, **kwargs)
            else:
                logger.warning(f"Role permission denied: {user_role} != {required_role}")
                return render_template(
                    "Error/AccessDenied.html",
                    message=f"Requires {required_role} role"
                ), 403

        return decorated_function

    return decorator


def validate_session_and_role(required_role):
    """Combine session validation and role check"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # First validate session
            session_response = validate_session(lambda: None)(*args, **kwargs)
            if session_response:
                return session_response

            # Then check role
            role_response = check_role_permission(required_role)(f)(*args, **kwargs)
            return role_response

        return decorated_function

    return decorator


# --- API Functions ---
def update_user_session(username, session_id):
    """Update session ID in database"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            query = """
                UPDATE "Users"
                SET "SessionId" = %s
                WHERE "UserName" = %s
            """
            cur.execute(query, (session_id, username))
            conn.commit()
            logger.info(f"Updated session for {username}")
            return True
    except Exception as e:
        logger.error(f"Session update failed: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            release_db_connection(conn)


def get_user_data(username, parameters):
    """Fetch user data from database"""
    if not parameters:
        return {"error": "Parameters required"}

    user_fields = {
        "UserName", "Role", "Active", "AllowedApps", "id", "SessionId"
    }
    profile_fields = {
        "FullName", "email", "Image", "ProjectLinks", "SocialAccounts", "Bio"
    }

    if parameters == "profiledata":
        user_params = user_fields
        profile_params = profile_fields
    else:
        user_params = set(parameters).intersection(user_fields)
        profile_params = set(parameters).intersection(profile_fields)

    result = {}
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            if user_params:
                query = f"""
                    SELECT {', '.join(f'"{col}"' for col in user_params)}
                    FROM "Users"
                    WHERE "UserName" = %s
                """
                cur.execute(query, (username,))
                user_data = cur.fetchone()
                if user_data:
                    result.update(dict(user_data))

            if profile_params:
                query = f"""
                    SELECT {', '.join(f'"{col}"' for col in profile_params)}
                    FROM "profiledata"
                    WHERE "UserName" = %s
                """
                cur.execute(query, (username,))
                profile_data = cur.fetchone()
                if profile_data:
                    result.update(dict(profile_data))

        return result if result else {"error": "User not found"}
    except Exception as e:
        logger.error(f"User data fetch error: {e}")
        return {"error": "Database error"}
    finally:
        if conn:
            release_db_connection(conn)
def authenticate_token(f):
    """
    Decorator to authenticate requests based on Authorization header token.
    Compares against MBKAUTHE_CONFIG["Main_SECRET_TOKEN"].
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config["MBKAUTHE_CONFIG"]
        provided_token = request.headers.get("Authorization")
        expected_token = config.get("Main_SECRET_TOKEN")

        if not expected_token:
             logger.error("authenticate_token: Main_SECRET_TOKEN is not configured.")
             abort(500, "Authentication token not configured on server.")


        # Simple direct comparison (consider more robust methods like Bearer token if needed)
        if provided_token and provided_token == expected_token:
            logger.info("authenticate_token: Authentication successful.")
            return f(*args, **kwargs)
        else:
            logger.warning(f"authenticate_token: Authentication failed. Provided: '{provided_token}'")
            abort(401, "Unauthorized") # Use abort for API-like responses

    return decorated_function

# --- Exports ---
__all__ = [
    'validate_session',
    'check_role_permission',
    'validate_session_and_role',
    'update_user_session',
    'get_user_data',
    'authenticate_token'
]