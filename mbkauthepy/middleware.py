import logging
import importlib.metadata
from pathlib import Path
from functools import wraps
from flask import session, request, current_app, jsonify, make_response
from datetime import datetime
import psycopg2
import psycopg2.extras
from .db import get_db_connection, release_db_connection

logger = logging.getLogger(__name__)

def get_cookie_options():
    """Get cookie configuration options based on deployment settings"""
    config = current_app.config.get("MBKAUTHE_CONFIG", {})
    options = {
        'path': '/',
        'httponly': True,
        'samesite': 'Lax'
    }

    if config.get('IS_DEPLOYED') == 'true':
        options['domain'] = f".{config.get('DOMAIN')}"
        options['secure'] = True
    else:
        options['secure'] = False

    return options

def clear_auth_cookies(response):
    """Clear authentication cookies from response"""
    options = get_cookie_options()
    cookie_names = ['mbkauthe.sid', 'sessionId', 'username']
    for name in cookie_names:
        response.delete_cookie(name, path=options.get('path'), domain=options.get('domain'),
                              secure=options.get('secure'), httponly=options.get('httponly'),
                              samesite=options.get('samesite'))

def _auth_error_response(code, error, message, pagename, page):
    """Handle error responses with Handlebars templates"""
    try:
        template_path = Path(__file__).parent / 'templates' / 'Error.handlebars'
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found at {template_path}")

        with open(template_path, 'r', encoding='utf-8') as f:
            template_source = f.read()

        from pybars import Compiler
        compiler = Compiler()
        template = compiler.compile(template_source)

        context = {
            'layout': False,
            'code': code,
            'error': error,
            'message': message,
            'pagename': pagename,
            'page': page
        }

        rendered = template(context)
        response = make_response(rendered, code)
        clear_auth_cookies(response)
        return response

    except Exception as e:
        logger.error(f"Error rendering error template: {e}")
        response = make_response(
            f"Error {code}: {error}\n{message}\nGo to {pagename} page: {page}",
            code
        )
        clear_auth_cookies(response)
        return response

def _restore_session_from_cookie():
    """Attempt to restore session from sessionId cookie"""
    if 'user' not in session and 'sessionId' in request.cookies:
        session_id = request.cookies.get('sessionId')
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = 'SELECT sess, expire, username FROM "session" WHERE sess->\'user\'->>\'sessionId\' = %s'
                cur.execute(query, (session_id,))
                session_record = cur.fetchone()

                if session_record and session_record['expire'] >= datetime.now():
                    user_data = session_record['sess']['user']
                    session['user'] = {
                        'id': user_data['id'],
                        'username': user_data['username'],
                        'role': user_data['role'],
                        'sessionId': session_id
                    }
                    logger.info(f"Restored session from cookie for user: {user_data['username']}")
                    return True
        except Exception as e:
            logger.error(f"Session restoration error: {e}", exc_info=True)
        finally:
            if conn:
                release_db_connection(conn)
    return False

def validate_session(f):
    """Middleware to validate user session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config.get("MBKAUTHE_CONFIG", {})

        if 'user' not in session:
            if not _restore_session_from_cookie():
                logger.warning("User not authenticated")
                return _auth_error_response(
                    code=401,
                    error="Not Logged In",
                    message="You Are Not Logged In. Please Log In To Continue.",
                    pagename="Login",
                    page=f"/mbkauthe/login?redirect={request.url}"
                )

        user_session = session['user']
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = """
                    SELECT sess, expire, username
                    FROM "session"
                    WHERE sess->'user'->>'sessionId' = %s
                """
                cur.execute(query, (user_session['sessionId'],))
                session_db = cur.fetchone()

                if not session_db or session_db['expire'] < datetime.now():
                    logger.warning(f"Session invalidated or expired for user {user_session['username']}")
                    session.clear()
                    return _auth_error_response(
                        code=401,
                        error="Session Expired",
                        message="Your Session Has Expired. Please Log In Again.",
                        pagename="Login",
                        page=f"/mbkauthe/login?redirect={request.url}"
                    )

                query = 'SELECT "Active", "Role", "AllowedApps" FROM "Users" WHERE "id" = %s'
                cur.execute(query, (user_session['id'],))
                user_db = cur.fetchone()

                if not user_db:
                    logger.warning(f"User not found: {user_session['username']}")
                    session.clear()
                    return _auth_error_response(
                        code=401,
                        error="Session Expired",
                        message="Your Session Has Expired. Please Log In Again.",
                        pagename="Login",
                        page=f"/mbkauthe/login?redirect={request.url}"
                    )

                if not user_db['Active']:
                    logger.warning(f"Inactive account: {user_session['username']}")
                    session.clear()
                    return _auth_error_response(
                        code=401,
                        error="Account Inactive",
                        message="Your Account Is Inactive. Please Contact Support.",
                        pagename="Support",
                        page="https://mbktechstudio.com/Support"
                    )

                app_name = config.get("APP_NAME")
                if user_db['Role'] != "SuperAdmin":
                    allowed_apps = user_db.get('AllowedApps') or []
                    if not any(app_name.lower() == app.lower() for app in allowed_apps):
                        logger.warning(f"User {user_session['username']} not authorized for {app_name}")
                        session.clear()
                        return _auth_error_response(
                            code=401,
                            error="Unauthorized",
                            message=f"You Are Not Authorized To Use The Application \"{app_name}\"",
                            pagename="Home",
                            page=f"/{config.get('loginRedirectURL')}"
                        )

            return f(*args, **kwargs)

        except Exception as e:
            logger.error(f"Session validation error: {e}", exc_info=True)
            return jsonify(success=False, message="Internal Server Error"), 500
        finally:
            if conn:
                release_db_connection(conn)

    return decorated_function

def check_role_permission(required_role=None, not_allowed=None):
    """Middleware factory for role-based permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            config = current_app.config.get("MBKAUTHE_CONFIG", {})

            if 'user' not in session:
                logger.warning("Role check failed: No session")
                return _auth_error_response(
                    code=401,
                    error="Not Logged In",
                    message="You Are Not Logged In. Please Log In To Continue.",
                    pagename="Login",
                    page=f"/mbkauthe/login?redirect={request.url}"
                )

            user_role = session['user'].get('role', '')

            if not_allowed and user_role == not_allowed:
                logger.warning(f"Role not allowed: {user_role}")
                return _auth_error_response(
                    code=403,
                    error="Access Denied",
                    message=f"You are not allowed to access this resource with role: {not_allowed}",
                    pagename="Home",
                    page=f"/{config.get('loginRedirectURL')}"
                )

            if required_role and required_role.lower() != "any":
                if user_role != required_role:
                    logger.warning(f"Role mismatch: Required {required_role}, has {user_role}")
                    return _auth_error_response(
                        code=403,
                        error="Access Denied",
                        message=f"You do not have permission to access this resource. Required role: {required_role}",
                        pagename="Home",
                        page=f"/{config.get('loginRedirectURL')}"
                    )

            return f(*args, **kwargs)

        return decorated_function

    return decorator

def validate_session_and_role(required_role=None, not_allowed=None):
    """Combined session validation and role check"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_validator = validate_session(lambda: None)
            session_response = session_validator()
            if session_response:
                return session_response

            role_checker = check_role_permission(required_role, not_allowed)(f)
            return role_checker(*args, **kwargs)

        return decorated_function

    return decorator

def authenticate_token(f):
    """Static token authentication middleware"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config.get("MBKAUTHE_CONFIG", {})
        provided_token = request.headers.get("Authorization", "")
        expected_token = config.get("Main_SECRET_TOKEN")

        if not expected_token:
            logger.error("Main_SECRET_TOKEN not configured")
            return jsonify(success=False, message="Server authentication misconfigured"), 500

        logger.debug(f"Received token: {provided_token}")

        if provided_token == expected_token:
            logger.info("Static token authentication successful")
            return f(*args, **kwargs)
        else:
            logger.warning("Static token authentication failed")
            return jsonify(success=False, message="Unauthorized"), 401

    return decorated_function

def authapi(required_role=None):
    """API key authentication with role validation"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            config = current_app.config.get("MBKAUTHE_CONFIG", {})
            token = request.headers.get("Authorization", "")
            logger.info(f"AuthAPI received token: {token[:3]}...{token[-3:]}")

            if not token:
                logger.warning("No API token provided")
                return jsonify(success=False, message="Authorization token is required"), 401

            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute('SELECT * FROM "UserAuthApiKey" WHERE "key" = %s', (token,))
                    token_record = cur.fetchone()

                    if not token_record:
                        logger.warning(f"Invalid API token: {token[:3]}...")
                        return jsonify(success=False, message="Invalid API token"), 401

                    username = token_record['username']
                    logger.info(f"Valid API token for user: {username}")

                    cur.execute(
                        'SELECT * FROM "Users" WHERE "UserName" = %s AND "Active" = TRUE',
                        (username,)
                    )
                    user = cur.fetchone()

                    if not user:
                        logger.warning(f"User not found or inactive: {username}")
                        return jsonify(success=False, message="User not found or inactive"), 401

                    if username.lower() == "demo":
                        logger.warning("Demo user API access denied")
                        return jsonify(
                            success=False,
                            message="Demo user not allowed for API access"
                        ), 401

                    user_role = user['Role']
                    if required_role and user_role != required_role and user_role != "SuperAdmin":
                        logger.warning(
                            f"Role permission denied. Required: {required_role}, Actual: {user_role}"
                        )
                        return jsonify(
                            success=False,
                            message=f"Access denied. Required role: {required_role}"
                        ), 403

                    request.api_user = {
                        'username': username,
                        'role': user_role
                    }

                    logger.info("API authentication successful")
                    return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"API authentication error: {e}", exc_info=True)
                return jsonify(success=False, message="Internal Server Error"), 500
            finally:
                if conn:
                    release_db_connection(conn)

        return decorated_function

    return decorator