import logging
from .config import MBKAUTHE_CONFIG

logger = logging.getLogger(__name__)

def get_cookie_options(http_only=True):
    """Returns a dictionary of options for setting cookies."""
    options = {
        "max_age": MBKAUTHE_CONFIG["COOKIE_EXPIRE_TIME_SECONDS"],
        "secure": MBKAUTHE_CONFIG["IS_DEPLOYED"],
        "samesite": 'Lax',
        "path": '/',
        "httponly": http_only
    }
    # Set domain only if deployed and not localhost
    if MBKAUTHE_CONFIG["IS_DEPLOYED"] and MBKAUTHE_CONFIG["DOMAIN"] != 'localhost':
        options["domain"] = f".{MBKAUTHE_CONFIG['DOMAIN']}"
    return options