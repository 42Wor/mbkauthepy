# MBKAUTHEPY

<p align="center">
  <img src="https://raw.githubusercontent.com/42Wor/mbkauthepy/refs/heads/main/docs/log.png" alt="MBKAUTHEPY Logo" width="180">
</p>

[![PyPI](https://img.shields.io/pypi/v/mbkauthepy?color=blue)](https://pypi.org/project/mbkauthepy/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Python Versions](https://img.shields.io/pypi/pyversions/mbkauthepy)](https://pypi.org/project/mbkauthepy/)
[![Downloads](https://img.shields.io/pypi/dm/mbkauthepy)](https://pypistats.org/packages/mbkauthepy)

> **mbkauthepy** is a fully featured, secure, and extensible authentication system for **Python Flask** applications.  
> Ported from the Node.js version to provide seamless **multi-language support** for full-stack apps.

---
## 📚 Table of Contents

- [✨ Features](#-features)
- [🧠 Multi-language Support](#-multilanguage-support)
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
## 🧠 Multi-language Support

This package is designed to work seamlessly with both **Python** and **JavaScript** applications.

- The **JavaScript** version is available on [npm](https://www.npmjs.com/package/mbkauthe) as `mbkauthe`.
- The **Python** version is available on [PyPI](https://pypi.org/project/mbkauthepy) as `mbkauthepy`.

### Repositories:
- **Python Version**: [mbkauthepy GitHub](https://github.com/42Wor/mbkauthepy)
- **JavaScript Version**: [mbkauthe GitHub](https://github.com/MIbnEKhalid/mbkauthe)

### Contact & Contributions:
- **Maaz Waheed** (Python Version)
  - GitHub: [@42Wor](https://github.com/42Wor)
  - Email: [maaz.waheed@mbktechstudio.com](mailto:maaz.waheed@mbktechstudio.com) / [wwork4287@gmail.com](mailto:wwork4287@gmail.com)
  
- **Muhammad Bin Khalid** (JavaScript Version)
  - GitHub: [@MIbnEKhalid](https://github.com/MIbnEKhalid)
  - For questions or contributions:
    - Support Page: [mbktechstudio.com/Support](http://mbktechstudio.com/Support)
    - Email: [support@mbktechstudio.com](mailto:support@mbktechstudio.com) / [chmuhammadbinkhalid28@gmail.com](mailto:chmuhammadbinkhalid28@gmail.com)

### Issues / PRs:
We welcome issues and pull requests! Feel free to contribute or ask any questions.

---

**Note**: This project is developed and maintained by **Maaz Waheed** and **Muhammad Bin Khalid**.

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
```

### 3. Install mbkauthepy

```bash
pip install mbkauthepy

```

---

## 🚀 Quickstart Example

```python
from flask import Flask, render_template, session
from dotenv import load_dotenv
from mbkauthepy import configure_mbkauthe, validate_session

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
    "APP_NAME": "MBKAUTH_PYTHON_DEMO",
    "IS_DEPLOYED": "false",
    "LOGIN_DB": "postgresql://username:password@host:port/database",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": "2", # In days
    "DOMAIN": "mbktechstudio.com", # Use your actual domain in production
    "Main_SECRET_TOKEN": "your-secret-token-for-terminate-api", # Added for terminateAllSessions auth
    "loginRedirectURL": "/",
    "EncryptedPassword": "False"
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

| Method | Endpoint                                                               | Description                                                    |
|--------|------------------------------------------------------------------------|----------------------------------------------------------------|
| POST   | `/mbkauthe/api/login`                                                  | Authenticate and create session                                |
| POST   | `/mbkauthe/api/logout`                                                 | Terminate current session                                      |
| POST   | `/mbkauthe/api/terminateAllSessions`                                   | Clears all sessions (admin only)                               |
| GET    | `/mbkauthe/i` or `/mbkauthe/info` or  `mbkauthe.mbkauthe_info`         | Current package version or metadata from the installed package |
| GET    | `mbkauthe.login_page` or `/mbkauthe/login`                             | login page in package                                          |


---

## 🗄️ Database Schema

👉 See [`docs/db.md`](docs/db.md) for schema & setup scripts.

---

## 🔐 Security Notes

- 🔐 Set `EncryptedPassword: "true"` for production use.
- ✅ Always use long random `SESSION_SECRET_KEY`.
- 🔒 Use HTTPS in deployment (`IS_DEPLOYED: "true"`).
- 🚫 Avoid plaintext passwords outside dev/testing.
 > **Note:** Encrypted password support is under development. Stay tuned for updates!
---

## 📜 License

**Mozilla Public License 2.0**  
See [LICENSE](./LICENSE) for full legal text.

---

## 🙋 Contact & Support

Developed by **Maaz Waheed**

- GitHub: [@42Wor](https://github.com/42Wor)
- Email: [maaz.waheed@mbktechstudio.com](mailto:maaz.waheed@mbktechstudio.com) / [wwork4287@gmail.com](mailto:wwork4287@gmail.com)
- Issues / PRs welcome!

---

Would you like me to generate:

- ✅ A `requirements.txt`
- ✅ The `.env` template
- ✅ Diagrams (e.g., session flow, DB schema)
- ✅ Frontend login template in HTML?

Let me know which extras you want!