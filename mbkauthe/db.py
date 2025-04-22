# mbkauthe/db.py (Simplified - No Pooling)

import psycopg2
import psycopg2.extras # Keep for DictCursor if used elsewhere
import logging
import os # Needed for environment variable access if MBKAUTHE_CONFIG isn't passed

# Import config loading logic or access config directly
# Assuming MBKAUTHE_CONFIG is loaded in config.py and accessible
try:
    from .config import MBKAUTHE_CONFIG
except ImportError:
    # Fallback or error handling if config structure is different
    # This might happen if db.py is imported before config is fully loaded
    # A better pattern might involve passing config explicitly or using Flask's app context
    logger = logging.getLogger(__name__)
    logger.warning("Could not import MBKAUTHE_CONFIG from .config in db.py. Ensure config is loaded.")
    # Attempt to load directly from env as a fallback (less ideal)
    try:
        import json
        from dotenv import load_dotenv
        load_dotenv()
        MBKAUTHE_CONFIG = json.loads(os.environ.get("mbkautheVar", "{}"))
        if not MBKAUTHE_CONFIG.get("LOGIN_DB"):
             raise ValueError("LOGIN_DB not found in mbkautheVar")
    except Exception as e:
         raise ImportError(f"Failed to load LOGIN_DB configuration for db.py: {e}")


logger = logging.getLogger(__name__)

# --- Removed Pooling Logic ---
# db_pool = None
# def init_db_pool(): ...
# def close_db_pool(): ...
# --- End Removed Pooling Logic ---

def get_db_connection():
    """Gets a new database connection for the current request."""
    logger.debug("Attempting to establish new DB connection.")
    try:
        # Get connection string from loaded config
        connection_string = MBKAUTHE_CONFIG.get("LOGIN_DB")
        if not connection_string:
            raise ValueError("LOGIN_DB configuration is missing.")

        # Create a new connection each time this function is called
        conn = psycopg2.connect(dsn=connection_string)
        logger.debug("New DB connection established.")
        return conn
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f"Database connection error: {error}", exc_info=True)
        # Raise a more specific error or handle as appropriate for your app
        raise ConnectionError("Failed to connect to the database.") from error

def release_db_connection(conn):
    """Closes the database connection."""
    if conn:
        try:
            conn.close()
            logger.debug("DB connection closed.")
        except (Exception, psycopg2.DatabaseError) as error:
             # Log error if closing fails, but don't typically raise
             # as the primary operation might have succeeded.
             logger.error(f"Error closing DB connection: {error}", exc_info=True)