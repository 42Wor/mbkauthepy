# mbkauthe/db.py

import psycopg2
import psycopg2.pool
import logging
from .config import MBKAUTHE_CONFIG

logger = logging.getLogger(__name__)

db_pool = None

def init_db_pool():
    """Initializes the PostgreSQL connection pool. Idempotent."""
    global db_pool
    if db_pool is not None:
        # logger.debug("Database pool already initialized.") # Optional: reduce log noise
        return db_pool

    logger.info("Initializing database connection pool...") # Log init attempt
    try:
        # Using ThreadedConnectionPool for multi-threaded Flask apps
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,  # Adjust maxconn as needed
            dsn=MBKAUTHE_CONFIG["LOGIN_DB"],
            # sslmode='require' # Adjust SSL mode based on your DB requirements
        )
        # Test connection
        conn = db_pool.getconn()
        logger.info("Connected to PostgreSQL database (pool)!")
        db_pool.putconn(conn)
        return db_pool
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f"Database connection pool initialization error: {error}")
        db_pool = None # Ensure pool is None if init fails
        raise # Re-raise the exception to signal failure

def get_db_connection():
    """Gets a connection from the pool. Initializes pool if necessary."""
    global db_pool
    # --- Modification Start ---
    if db_pool is None:
        logger.warning("Database pool was not initialized. Attempting to initialize now.")
        try:
            # Try to initialize it before proceeding
            init_db_pool()
            # Check again if initialization failed
            if db_pool is None:
                 logger.error("Failed to initialize database pool on demand.")
                 raise ConnectionError("Database pool initialization failed.")
        except Exception as e:
             # Catch potential errors during the on-demand init
             logger.error(f"Failed to auto-initialize pool in get_db_connection: {e}")
             raise ConnectionError("Database pool could not be initialized.") from e
    # --- Modification End ---

    # Now db_pool should exist (unless init failed above)
    try:
        return db_pool.getconn()
    except psycopg2.pool.PoolError as e:
        logger.error(f"Error getting connection from pool: {e}")
        raise
    except AttributeError:
         # Safety net in case db_pool is None despite the check (shouldn't happen often)
         logger.error("AttributeError: db_pool became None unexpectedly before getting connection.")
         raise ConnectionError("Database pool is unexpectedly unavailable.")


def release_db_connection(conn):
    """Releases a connection back to the pool."""
    global db_pool
    if db_pool is None:
        # Don't log warning every time if pool is intentionally closed
        # logger.warning("Database pool is not initialized. Cannot release connection.")
        return
    if conn:
        try:
            db_pool.putconn(conn)
        except Exception as e:
             # Log error if putting connection back fails (e.g., pool closed)
             logger.error(f"Error releasing DB connection: {e}")


def close_db_pool():
    """Closes all connections in the pool."""
    global db_pool
    if db_pool:
        try:
            db_pool.closeall()
            logger.info("Database connection pool closed.")
        except Exception as e:
             logger.error(f"Error closing database pool: {e}")
        finally:
             # Crucially set to None after closing
             db_pool = None
    # else: # Optional: reduce log noise
    #     logger.debug("Database pool already closed or not initialized.")

# Remove automatic initialization here - let configure_mbkauthe handle it
# init_db_pool()