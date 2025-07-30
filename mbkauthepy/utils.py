# mbkauthepy/utils.py

import logging
from functools import wraps
from flask import current_app, request, session
import psycopg2
import psycopg2.extras
from werkzeug.exceptions import Unauthorized, Forbidden

logger = logging.getLogger(__name__)


def get_cookie_options():
    """
    Get cookie configuration options based on deployment settings.
    Returns a dictionary of cookie options.
    """
    config = current_app.config.get("MBKAUTHE_CONFIG", {})
    options = {
        'path': '/',
        'httponly': True,
        'samesite': 'Lax',
        'max_age': int(config.get('COOKIE_EXPIRE_TIME', 30)) * 24 * 60 * 60  # Convert days to seconds
    }

    if config.get('IS_DEPLOYED') == 'true':
        options['domain'] = f".{config.get('DOMAIN')}"
        options['secure'] = True
    else:
        options['secure'] = False

    return options


def get_user_data(user_id=None, username=None):
    """
    Retrieve complete user data from the database.
    Can query by either user_id or username (prioritizes user_id if both provided).

    Args:
        user_id (int): The user's ID
        username (str): The user's username

    Returns:
        dict: Complete user data as a dictionary or None if not found
    """
    if not user_id and not username:
        raise ValueError("Either user_id or username must be provided")

    conn = None
    try:
        conn = current_app.db_pool.getconn()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            if user_id:
                query = 'SELECT * FROM "Users" WHERE "id" = %s'
                params = (user_id,)
            else:
                query = 'SELECT * FROM "Users" WHERE "UserName" = %s'
                params = (username,)

            cur.execute(query, params)
            user = cur.fetchone()
            return dict(user) if user else None

    except Exception as e:
        logger.error(f"Error fetching user data: {e}", exc_info=True)
        raise
    finally:
        if conn:
            current_app.db_pool.putconn(conn)


def clear_auth_cookies(response):
    """Clear authentication cookies from response"""
    options = get_cookie_options()
    cookie_names = ['mbkauthe.sid', 'sessionId', 'username']
    for name in cookie_names:
        response.delete_cookie(name, path=options.get('path'), domain=options.get('domain'),
                              secure=options.get('secure'), httponly=options.get('httponly'),
                              samesite=options.get('samesite'))

def generate_session_id():
    """
    Generate a secure session ID.
    In production, should use a cryptographically secure method.
    """
    import secrets
    import hashlib
    import time

    raw_token = f"{secrets.token_hex(16)}{time.time()}"
    return hashlib.sha256(raw_token.encode()).hexdigest()


def validate_api_key(api_key):
    """
    Validate an API key against the database.

    Args:
        api_key (str): The API key to validate

    Returns:
        dict: User data if valid, None otherwise
    """
    conn = None
    try:
        conn = current_app.db_pool.getconn()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Check API key validity
            cur.execute(
                'SELECT u.* FROM "Users" u '
                'JOIN "UserAuthApiKey" k ON u."UserName" = k."username" '
                'WHERE k."key" = %s AND u."Active" = TRUE',
                (api_key,)
            )
            user = cur.fetchone()
            return dict(user) if user else None

    except Exception as e:
        logger.error(f"API key validation error: {e}", exc_info=True)
        raise
    finally:
        if conn:
            current_app.db_pool.putconn(conn)


def get_current_user():
    """
    Get the current authenticated user's data.

    Returns:
        dict: Complete user data or None if not authenticated
    """
    if 'user' not in session:
        return None

    return get_user_data(user_id=session['user'].get('id'))


def role_required(*roles):
    """
    Decorator factory for role-based access control.

    Args:
        *roles: Allowed roles (can specify 'any' for any authenticated user)

    Returns:
        function: Decorator function
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user' not in session:
                raise Unauthorized("Authentication required")

            user_role = session['user'].get('role')
            if 'any' not in roles and user_role not in roles:
                raise Forbidden("Insufficient permissions")

            return f(*args, **kwargs)

        return wrapped

    return decorator


def app_authorized(app_name):
    """
    Check if the current user is authorized for the specified application.

    Args:
        app_name (str): The application name to check

    Returns:
        bool: True if authorized, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # SuperAdmin has access to everything
    if user.get('Role') == 'SuperAdmin':
        return True

    allowed_apps = user.get('AllowedApps', [])
    return app_name.lower() in [app.lower() for app in allowed_apps]