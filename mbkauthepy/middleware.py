import logging
from functools import wraps
from flask import session, request, jsonify, render_template, current_app, make_response, abort
import psycopg2
import psycopg2.extras # For dictionary cursor
from .db import get_db_connection, release_db_connection
from .utils import get_cookie_options

logger = logging.getLogger(__name__)

# --- Session Restoration Helper ---
def _restore_session_from_cookie():
    """Attempts to restore session from sessionId cookie if Flask session is missing."""
    if 'user' not in session and 'sessionId' in request.cookies:
        session_id_cookie = request.cookies.get('sessionId')
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = """
                    SELECT id, "UserName", "Role", "SessionId"
                    FROM "Users" WHERE "SessionId" = %s AND "Active" = TRUE
                """
                cur.execute(query, (session_id_cookie,))
                user = cur.fetchone()

                if user and user['SessionId'] == session_id_cookie:
                    logger.info(f"Restoring session for user: {user['UserName']}")
                    session['user'] = {
                        'id': user['id'],
                        'username': user['UserName'],
                        'role': user['Role'],
                        'sessionId': user['SessionId']
                    }
                    session.permanent = True # Ensure session uses configured lifetime
                    return True # Session restored
        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"Session restoration error: {e}")
            # Clear potentially invalid cookie if restoration fails
            # resp = make_response("Session restoration failed") # Or redirect
            # resp.delete_cookie('sessionId', **get_cookie_options())
            # return resp # Or handle differently
        finally:
            if conn:
                release_db_connection(conn)
    return False # Session not restored or already exists

# --- Decorator: validate_session ---
def validate_session(f):
    """
    Decorator to validate user session. Checks DB for validity, activity, and app access.
    Renders error pages or proceeds.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = current_app.config["MBKAUTHE_CONFIG"]
        restored = _restore_session_from_cookie()

        if 'user' not in session:
            logger.warning("validate_session: User not authenticated (no session).")
            return render_template("Error/NotLoggedIn.html", currentUrl=request.url), 401

        user_session = session['user']
        user_id = user_session.get('id')
        session_id = user_session.get('sessionId')

        if not user_id or not session_id:
             logger.error("validate_session: Invalid session data (missing id or sessionId).")
             session.clear()
             resp = make_response(render_template("Error/SessionExpire.html", currentUrl=request.url))
             # Clear cookies just in case
             resp.delete_cookie('sessionId', **get_cookie_options())
             resp.delete_cookie('username', **get_cookie_options(http_only=False))
             return resp, 401

        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                query = """
                    SELECT "SessionId", "Active", "Role", "AllowedApps"
                    FROM "Users" WHERE "id" = %s
                """
                cur.execute(query, (user_id,))
                user_db = cur.fetchone()

            if not user_db or user_db['SessionId'] != session_id:
                logger.warning(f"validate_session: Session invalidated for user '{user_session.get('username', 'N/A')}' (DB mismatch or user not found).")
                session.clear()
                resp = make_response(render_template("Error/SessionExpire.html", currentUrl=request.url))
                resp.delete_cookie('sessionId', **get_cookie_options())
                resp.delete_cookie('username', **get_cookie_options(http_only=False))
                return resp, 401

            if not user_db['Active']:
                logger.warning(f"validate_session: Account inactive for user '{user_session.get('username', 'N/A')}'.")
                session.clear()
                resp = make_response(render_template("Error/AccountInactive.html", currentUrl=request.url))
                resp.delete_cookie('sessionId', **get_cookie_options())
                resp.delete_cookie('username', **get_cookie_options(http_only=False))
                return resp, 403

            # Check App Access (if not SuperAdmin)
            if user_db['Role'] != "SuperAdmin":
                allowed_apps = user_db['AllowedApps'] or []
                app_name = config["APP_NAME"]
                if app_name not in allowed_apps:
                    logger.warning(f"validate_session: User '{user_session.get('username', 'N/A')}' not authorized for app '{app_name}'.")
                    session.clear()
                    resp = make_response(render_template("Error/Error.html", error=f"You Are Not Authorized To Use The Application \"{app_name}\""))
                    resp.delete_cookie('sessionId', **get_cookie_options())
                    resp.delete_cookie('username', **get_cookie_options(http_only=False))
                    return resp, 403

            # Session is valid, proceed with the original function
            return f(*args, **kwargs)

        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"validate_session: Database error: {e}")
            return render_template("Error/Error.html", error="Internal Server Error during session validation."), 500
        finally:
            if conn:
                release_db_connection(conn)

    return decorated_function

# --- Decorator: check_role_permission ---
def check_role_permission(required_role):
    """
    Decorator factory to check if the user in session has the required role.
    Must be used *after* @validate_session or ensure session['user']['role'] exists.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session or 'role' not in session['user']:
                # This should ideally be caught by validate_session first
                logger.error("check_role_permission: No user or role found in session.")
                return render_template("Error/NotLoggedIn.html", currentUrl=request.url), 401

            user_role = session['user']['role']

            # Allow if role is "Any" or matches exactly
            if required_role.lower() == "any" or user_role == required_role:
                return f(*args, **kwargs)
            else:
                logger.warning(f"check_role_permission: Access denied for user '{session['user'].get('username', 'N/A')}'. Required: '{required_role}', Has: '{user_role}'.")
                return render_template("Error/AccessDenied.html", currentRole=user_role, requiredRole=required_role), 403
        return decorated_function
    return decorator

# --- Decorator: validate_session_and_role ---
def validate_session_and_role(required_role):
    """
    Decorator factory combining session validation and role checking.
    """
    def decorator(f):
        # Apply decorators in reverse order of execution
        # validate_session runs first, then check_role_permission
        @wraps(f)
        @check_role_permission(required_role)
        @validate_session
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Decorator: authenticate_token ---
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


# --- Function: get_user_data ---
def get_user_data(username, parameters):
    """
    Fetches specified user data fields from Users and profiledata tables.

    Args:
        username (str): The UserName of the user.
        parameters (list or str): A list of field names or the string "profiledata".

    Returns:
        dict: Combined user data or {'error': 'message'}.
    """
    if not parameters:
        return {"error": "Parameters are required to fetch user data"}

    # Define available fields (excluding password by default unless explicitly requested)
    user_fields = {
        "UserName", "Role", "Active", "GuestRole", "HaveMailAccount", "AllowedApps", "id", "SessionId" # Added id/SessionId
    }
    profile_fields = {
        "FullName", "email", "Image", "ProjectLinks", "SocialAccounts", "Bio", "Positions"
    }
    password_field = {"Password"} # Handle separately for security

    user_params_req = set()
    profile_params_req = set()
    fetch_password = False

    if parameters == "profiledata":
        user_params_req = user_fields
        profile_params_req = profile_fields
    elif isinstance(parameters, list):
        requested_set = set(parameters)
        user_params_req = requested_set.intersection(user_fields)
        profile_params_req = requested_set.intersection(profile_fields)
        if "Password" in requested_set:
            fetch_password = True
            # Ensure UserName is always fetched if password is needed (though query uses it)
            user_params_req.add("UserName")
    else:
        return {"error": "Invalid parameters type. Must be list or 'profiledata'."}

    # Always fetch UserName for identification, even if not requested explicitly in list
    if user_params_req:
        user_params_req.add("UserName")
    if profile_params_req:
         # profiledata table likely uses UserName as key
         pass # No extra fields needed here usually

    combined_result = {}
    conn = None

    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Fetch from Users table
            if user_params_req or fetch_password:
                select_cols = list(user_params_req)
                if fetch_password:
                    select_cols.append("Password") # Add password field if requested

                # Ensure unique columns and quote them
                select_clause = ", ".join([f'"{col}"' for col in set(select_cols)])

                user_query = f'SELECT {select_clause} FROM "Users" WHERE "UserName" = %s'
                cur.execute(user_query, (username,))
                user_result = cur.fetchone()
                if not user_result:
                    return {"error": "User not found"}
                combined_result.update(dict(user_result))
                 # Remove password unless explicitly requested
                if "Password" in combined_result and not fetch_password:
                    del combined_result["Password"]


            # Fetch from profiledata table
            if profile_params_req:
                 # Ensure unique columns and quote them
                select_clause = ", ".join([f'"{col}"' for col in profile_params_req])
                profile_query = f'SELECT {select_clause} FROM profiledata WHERE "UserName" = %s'
                cur.execute(profile_query, (username,))
                profile_result = cur.fetchone()
                if not profile_result:
                    # Decide if this is an error or just means no profile data
                    logger.warning(f"No profile data found for user '{username}'.")
                    # return {"error": "Profile data not found"} # Or just return user data
                else:
                    combined_result.update(dict(profile_result))

        return combined_result

    except (Exception, psycopg2.DatabaseError) as e:
        logger.error(f"Error fetching user data for '{username}': {e}")
        # Don't expose detailed errors generally
        return {"error": "Internal server error while fetching user data."}
    finally:
        if conn:
            release_db_connection(conn)