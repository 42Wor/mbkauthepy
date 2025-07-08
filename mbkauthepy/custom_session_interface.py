# custom_session_interface.py

import logging
import json
import secrets
from datetime import datetime, timezone, timedelta
# Import SessionInterface and SessionMixin from the correct module
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict
import psycopg2
import psycopg2.extras

# Import your DB connection functions from mbkauthe
try:
    # Assuming mbkauthe is installed/accessible relative to app.py
    from .db import get_db_connection, release_db_connection
except ImportError:
    # Provide a more specific error if the import fails
    raise ImportError("Could not import DB functions from mbkauthepy.db. Check mbkauthepy installation and structure.")

logger = logging.getLogger(__name__)

class DbSession(CallbackDict, SessionMixin):
    """Custom session object based on Werkzeug's CallbackDict."""
    def __init__(self, initial=None, sid=None, permanent=None):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        # Set permanence based on the value passed during creation
        if permanent is not None:
            self.permanent = permanent
        else:
            # Default permanence if not explicitly provided (should be provided by interface)
            self.permanent = True # Default to permanent if not specified
        self.modified = False

class CustomDbSessionInterface(SessionInterface):
    """
    A custom Flask SessionInterface that reads/writes session data
    to a PostgreSQL table with columns: sid, sess (JSON/TEXT), expire.
    """
    session_class = DbSession
    serializer = json # Use JSON for serialization/deserialization

    def __init__(self, table='session'):
        self.table = table # Table name

    def _generate_sid(self):
        """Generates a cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _get_expiration_time(self, app, session):
        """Calculates the expiration datetime object based on Flask config."""
        if session.permanent:
            lifetime = app.config.get('PERMANENT_SESSION_LIFETIME', timedelta(days=31))
        else:
            lifetime = app.config.get('NON_PERMANENT_SESSION_LIFETIME', timedelta(hours=1))
        return datetime.now(timezone.utc) + lifetime

    def open_session(self, app, request):
        """Called by Flask to retrieve an existing session or create a new one."""
        session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        sid = request.cookies.get(session_cookie_name)

        # --- FIX APPLIED HERE (and below) ---
        # Determine default permanence for NEW sessions from app config
        default_is_permanent = app.config.get('SESSION_PERMANENT', True)
        # --- END FIX ---

        if not sid:
            sid = self._generate_sid()
            logger.debug(f"No session cookie found, generating new sid: {sid}")
            # --- FIX APPLIED HERE ---
            return self.session_class(sid=sid, permanent=default_is_permanent)
            # --- END FIX ---

        conn = None
        logger.debug(f"Attempting to open session for sid: {sid}")
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    f'SELECT sess, expire FROM "{self.table}" WHERE sid = %s',
                    (sid,)
                )
                data = cur.fetchone()

            db_expire_utc = None
            if data and data['expire']:
                 if data['expire'].tzinfo is None:
                     db_expire_utc = data['expire'].replace(tzinfo=timezone.utc)
                 else:
                     db_expire_utc = data['expire'].astimezone(timezone.utc)

            if data and db_expire_utc and db_expire_utc > datetime.now(timezone.utc):
                logger.debug(f"Session found in DB for sid: {sid}")
                try:
                    session_data_raw = data['sess']
                    if isinstance(session_data_raw, dict):
                         session_data = session_data_raw
                    elif isinstance(session_data_raw, str):
                         session_data = self.serializer.loads(session_data_raw)
                    else:
                         logger.warning(f"Unexpected session data type from DB: {type(session_data_raw)}")
                         raise TypeError("Session data from DB is not a dict or string")
                    # When loading an existing session, its permanence is part of its data
                    # The session_class constructor handles setting self.permanent
                    return self.session_class(session_data, sid=sid)
                except (json.JSONDecodeError, TypeError, KeyError) as e:
                    logger.warning(f"Failed to decode/load session data for sid {sid}: {e}. Creating new session.")
                    sid = self._generate_sid()
                    # --- FIX APPLIED HERE ---
                    return self.session_class(sid=sid, permanent=default_is_permanent)
                    # --- END FIX ---
            else:
                if data:
                     logger.debug(f"Session expired for sid: {sid}")
                else:
                     logger.debug(f"Session not found in DB for sid: {sid}")
                sid = self._generate_sid()
                # --- FIX APPLIED HERE ---
                return self.session_class(sid=sid, permanent=default_is_permanent)
                # --- END FIX ---

        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"Error opening session (sid: {sid}): {e}", exc_info=True)
            sid = self._generate_sid()
            # --- FIX APPLIED HERE ---
            return self.session_class(sid=sid, permanent=default_is_permanent)
            # --- END FIX ---
        finally:
            if conn:
                release_db_connection(conn)

    def save_session(self, app, session, response):
        """Called by Flask to save the session data at the end of a request."""
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')

        # Use SessionInterface's method to calculate cookie expiration based on session lifetime
        # This uses session.permanent which was set when the session was opened/created
        expires = self.get_expiration_time(app, session)

        if not session:
            if session.modified:
                logger.debug(f"Session cleared, attempting to delete from DB: {session.sid}")
                conn = None
                try:
                    conn = get_db_connection()
                    with conn.cursor() as cur:
                        cur.execute(f'DELETE FROM "{self.table}" WHERE sid = %s', (session.sid,))
                    conn.commit()
                    logger.debug(f"Deleted session from DB: {session.sid}")
                except (Exception, psycopg2.DatabaseError) as e:
                    logger.error(f"Error deleting session (sid: {session.sid}): {e}", exc_info=True)
                    if conn: conn.rollback()
                finally:
                    if conn: release_db_connection(conn)
                response.delete_cookie(
                    session_cookie_name, domain=domain, path=path,
                    secure=secure, httponly=httponly, samesite=samesite
                )
            return

        if not session.modified:
            if self.should_set_cookie(app, session):
                 logger.debug(f"Session not modified but setting cookie for sid: {session.sid}")
                 response.set_cookie(
                    session_cookie_name, session.sid, expires=expires,
                    httponly=httponly, domain=domain, path=path, secure=secure, samesite=samesite
                )
            return

        conn = None
        logger.debug(f"Session modified, attempting to save to DB: {session.sid}")
        try:
            session_data_json = self.serializer.dumps(dict(session))
            # Calculate DB expiration using our helper, which respects session.permanent
            db_expires = self._get_expiration_time(app, session)

            conn = get_db_connection()
            with conn.cursor() as cur:
                upsert_sql = f"""
                    INSERT INTO "{self.table}" (sid, sess, expire,username)
                    VALUES (%s, %s, %s,%s)
                    ON CONFLICT (sid) DO UPDATE SET
                        sess = EXCLUDED.sess,
                        expire = EXCLUDED.expire;
                """
                cur.execute(upsert_sql, (session.sid, session_data_json, db_expires,session.get('username')))
            conn.commit()
            logger.debug(f"Saved session to DB: {session.sid}")

            response.set_cookie(
                session_cookie_name, session.sid, expires=expires,
                httponly=httponly, domain=domain, path=path, secure=secure, samesite=samesite
            )

        except (Exception, psycopg2.DatabaseError) as e:
            logger.error(f"Error saving session (sid: {session.sid}): {e}", exc_info=True)
            if conn: conn.rollback()
        finally:
            if conn: release_db_connection(conn)