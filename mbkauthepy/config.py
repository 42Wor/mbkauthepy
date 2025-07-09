# mbkauthe/config.py

import os
import json
from dotenv import load_dotenv
from datetime import timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()


class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass


def load_config():
    """Loads and validates configuration from environment variables."""
    mbkauthe_var_str = os.environ.get("mbkautheVar")
    if not mbkauthe_var_str:
        raise ConfigError("Environment variable 'mbkautheVar' is not set.")

    try:
        config = json.loads(mbkauthe_var_str)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in 'mbkautheVar': {e}")

    # --- Validation ---
    required_keys = [
        "APP_NAME", "SESSION_SECRET_KEY", "IS_DEPLOYED",
        "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN", "Main_SECRET_TOKEN",
         "EncryptedPassword","loginRedirectURL"
    ]
    for key in required_keys:
        if key not in config or config[key] is None:
            raise ConfigError(f"Missing required configuration key: mbkautheVar.{key}")
    # Convert string booleans to actual booleans
    config["IS_DEPLOYED"] = str(config.get("IS_DEPLOYED", "false")).lower() == 'true'
    config["MBKAUTH_TWO_FA_ENABLE"] = str(config.get("MBKAUTH_TWO_FA_ENABLE", "false")).lower() == 'true'
    config["EncryptedPassword"] = str(config.get("EncryptedPassword", "false")).lower() == 'true'

    # Handle optional reCAPTCHA config
    config["RECAPTCHA_Enabled"] = str(config.get("RECAPTCHA_Enabled", "false")).lower() == 'true'
    if config["RECAPTCHA_Enabled"] and not config.get("RECAPTCHA_SECRET_KEY"):
        raise ConfigError("mbkautheVar.RECAPTCHA_SECRET_KEY is required when RECAPTCHA_Enabled is true.")

    # Cookie Expire Time (in days)
    try:
        expire_days = float(config.get("COOKIE_EXPIRE_TIME", 2))  # Default 2 days
        if expire_days <= 0:
            raise ValueError("COOKIE_EXPIRE_TIME must be positive.")
        config["COOKIE_EXPIRE_TIME_SECONDS"] = int(expire_days * 24 * 60 * 60)
        config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=expire_days)
    except (ValueError, TypeError):
        logger.warning("Invalid COOKIE_EXPIRE_TIME, using default 2 days.")
        config["COOKIE_EXPIRE_TIME_SECONDS"] = 2 * 24 * 60 * 60
        config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=2)

    # Bypass Users
    bypass_users = config.get("BypassUsers", [])
    if isinstance(bypass_users, str):
        try:
            parsed_bypass = json.loads(bypass_users)
            if isinstance(parsed_bypass, list):
                config["BypassUsers"] = parsed_bypass
            else:
                raise ConfigError("mbkautheVar.BypassUsers must be a valid JSON array string or list.")
        except (json.JSONDecodeError, TypeError):
            raise ConfigError("mbkautheVar.BypassUsers must be a valid list or JSON array string.")
    elif not isinstance(bypass_users, list):
        raise ConfigError("mbkautheVar.BypassUsers must be a valid list or JSON array string.")
    else:
        config["BypassUsers"] = bypass_users

    logger.info("Configuration loaded successfully.")
    return config


# Load config globally for the package
try:
    MBKAUTHE_CONFIG = load_config()
except ConfigError as e:
    logger.error(f"Configuration Error: {e}")
    # For a library, raising is better than exiting. The main application can catch it.
    raise


# --- Flask App Configuration Function ---
def configure_flask_app(app):
    """Applies mbkauthe configuration to a Flask app instance."""
    app.config["SECRET_KEY"] = MBKAUTHE_CONFIG["SESSION_SECRET_KEY"]

    # Flask-Session configuration

    app.config["SESSION_PERMANENT"] = True  # Use expiration
    app.config["PERMANENT_SESSION_LIFETIME"] = MBKAUTHE_CONFIG["PERMANENT_SESSION_LIFETIME"]
    app.config["SESSION_USE_SIGNER"] = True  # Encrypt session cookie content
    app.config["SESSION_COOKIE_NAME"] = "mbkauthe.sid"  # Match JS name
    app.config["SESSION_COOKIE_SECURE"] = MBKAUTHE_CONFIG["IS_DEPLOYED"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
    app.config["SESSION_COOKIE_PATH"] = '/'
    if MBKAUTHE_CONFIG["IS_DEPLOYED"] and MBKAUTHE_CONFIG["DOMAIN"] != 'localhost':
        app.config["SESSION_COOKIE_DOMAIN"] = f".{MBKAUTHE_CONFIG['DOMAIN']}"


    # Store mbkauthe config within Flask app config for easy access
    app.config["MBKAUTHE_CONFIG"] = MBKAUTHE_CONFIG
    logger.info("Flask app configured for mbkauthe.")