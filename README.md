# 🔐 mbkauthe (Python/Flask Version)

[![PyPI](https://img.shields.io/pypi/v/mbkauthe?color=blue)](https://pypi.org/project/mbkauthe/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Build](https://img.shields.io/github/actions/workflow/status/42Wor/mbkauthe/python-app.yml?label=build)](https://github.com/42Wor/mbkauthe/actions)
[![Python Versions](https://img.shields.io/pypi/pyversions/mbkauthe)](https://pypi.org/project/mbkauthe/)
[![Downloads](https://img.shields.io/pypi/dm/mbkauthe)](https://pypistats.org/packages/mbkauthe)

> A fully featured, secure, and extensible authentication system for **Python Flask** applications.  
> Originally ported from the Node.js version to provide **multi-language support** for full-stack apps.

---

## 📚 Table of Contents

- [✨ Features](#-features)
- [📦 Installation](#-installation)
- [🚀 Quickstart](#-quickstart)
- [⚙️ Configuration (.env)](#️-configuration-env)
- [🧩 Middleware & Decorators](#-middleware--decorators)
- [🧪 API Endpoints](#-api-endpoints)
- [🗄️ Database Schema](#️-database-schema)
- [🔐 Security Notes](#-security-notes)
- [📜 License](#-license)
- [🙋 Contact & Support](#-contact--support)

---

## ✨ Features

| Feature                  | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| 🧠 Multi-language Support | Use in both Python (`mbkauthe`) and JavaScript (`mbkauthe` via [npm](https://github.com/MIbnEKhalid/mbkauthe))         |
| 🔒 Secure Auth           | Session-based authentication with secure cookies and optional 2FA          |
| 🧑‍🤝‍🧑 Role-based Access | Decorators for validating roles and permissions on protected routes         |
| 🔐 2FA Support           | Time-based One-Time Password (TOTP) with `pyotp`                            |
| 🔎 reCAPTCHA v2 Support  | Protect login routes with Google reCAPTCHA                                 |
| 🍪 Cookie Management     | Secure session cookies with custom expiration, domain, etc.                |
| 🐘 PostgreSQL Integration | Optimized with connection pooling via `psycopg2`                            |
| 🔑 Password Security     | Bcrypt hash support (or optional plaintext in dev/test mode)               |
| 🧠 Profile Data Access   | Built-in helper to fetch user profile details from DB                      |

---

## 📦 Installation

### 1. Python & Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\activate  # Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
# OR manually:
pip install Flask Flask-Session psycopg2-binary python-dotenv bcrypt requests pyotp Flask-Cors SQLAlchemy
```

### 3. Install mbkauthe

```bash
pip install -e ./mbkauthe  # Local dev
# OR if published:
# pip install mbkauthe
```

---

## 🚀 Quickstart Example

```python
from flask import Flask, render_template, session
from dotenv import load_dotenv
from src.mbkauthe import configure_mbkauthe, validate_session

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

configure_mbkauthe(app)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@validate_session
def dashboard():
    user = session['user']
    return f"Welcome {user['username']}!"


if __name__ == '__main__':
    app.run(debug=True)
```

---

## ⚙️ Configuration (.env)

```dotenv
FLASK_SECRET_KEY=my-flask-secret

mbkautheVar='{
  "APP_NAME": "MyApp",
  "RECAPTCHA_Enabled": "false",
  "SESSION_SECRET_KEY": "super-long-random-secret",
  "IS_DEPLOYED": "false",
  "LOGIN_DB": "postgresql://user:pass@host:5432/mydb",
  "MBKAUTH_TWO_FA_ENABLE": "false",
  "COOKIE_EXPIRE_TIME": "7",
  "DOMAIN": "localhost",
  "Main_SECRET_TOKEN": "internal-api-secret-token",
  "SESSION_TYPE": "sqlalchemy",
  "SESSION_SQLALCHEMY_TABLE": "session",
  "EncryptedPassword": "true"
}'
```

✅ You can override behavior by editing this JSON string directly in `.env`.

---

## 🧩 Middleware & Decorators

| Decorator | Purpose |
|----------|---------|
| `@validate_session` | Ensures valid session is active |
| `@check_role_permission("Role")` | Checks if user has required role |
| `@validate_session_and_role("Role")` | Shortcut for validating both |
| `@authenticate_token` | Verifies request via API token header |

Example:

```python
from src.mbkauthe import validate_session, check_role_permission, validate_session_and_role, authenticate_token


@app.route('/admin')
@validate_session_and_role("SuperAdmin")
def admin_panel():
    return "Welcome to the admin panel"


@app.route('/dashboard')
@validate_session
def dashboard():
    user = session['user']
    return f"Welcome {user['username']}"


@app.route('/secured-admin')
@validate_session_and_role("SuperAdmin")
def secured_admin():
    return "Secured Area"


@app.route('/terminate-sessions')
@authenticate_token
def terminate_sessions():
    return {"success": True}


# Example of fetching user data
data = get_user_data("johndoe", ["FullName", "email"])
```

---

## 🧪 API Endpoints

These are available by default after calling `configure_mbkauthe(app)`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/mbkauthe/api/login` | Authenticate and create session |
| POST | `/mbkauthe/api/logout` | Terminate current session |
| POST | `/mbkauthe/api/terminateAllSessions` | Clears all sessions (admin only) |
| GET  | `/mbkauthe/version` | Current package version |
| GET  | `/mbkauthe/package` | Metadata from installed package |
| GET  | `/mbkauthe/package-lock` | Dependency info (experimental) |

---

## 🗄️ Database Schema

| Table     | Purpose                              |
|-----------|--------------------------------------|
| `Users`   | Stores core user account info        |
| `sess`    | Tracks session info per user         |
| `TwoFA`   | Stores 2FA TOTP secrets              |
| `profiledata` | (Optional) Extended profile fields |

👉 See [`docs/db.md`](docs/db.md) for schema & setup scripts.

---

## 🔐 Security Notes

- 🔐 Set `EncryptedPassword: "true"` for production use.
- ✅ Always use long random `SESSION_SECRET_KEY`.
- 🔒 Use HTTPS in deployment (`IS_DEPLOYED: "true"`).
- 🚫 Avoid plaintext passwords outside dev/testing.

Need to hash a password?

```python
import bcrypt
hashed = bcrypt.hashpw(b"mypassword", bcrypt.gensalt())
```

---

## 📜 License

**Mozilla Public License 2.0**  
See [LICENSE](./LICENSE) for full legal text.

---

## 🙋 Contact & Support

Developed by **Maaz Waheed**

- GitHub: [@42Wor](https://github.com/42Wor)
- Issues / PRs welcome!

---

Would you like me to generate:

- ✅ A `requirements.txt`
- ✅ The `.env` template
- ✅ Diagrams (e.g., session flow, DB schema)
- ✅ Frontend login template in HTML?

Let me know which extras you want!