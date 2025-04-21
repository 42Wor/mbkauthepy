
# mbkauthepy (Python/Flask Version)

[![PyPI version](https://img.shields.io/pypi/v/mbkauthe.svg)](https://pypi.org/project/mbkauthe/)
[![Python Version](https://img.shields.io/pypi/pyversions/mbkauthe.svg)](https://pypi.org/project/mbkauthe/)
[![CodeQL](https://github.com/42Wor/YOUR_REPO_NAME/actions/workflows/codeql.yml/badge.svg)](https://github.com/42Wor/YOUR_REPO_NAME/actions/workflows/codeql.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

---

## 📚 Table of Contents

- [Features](#features)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Setup](#basic-setup)
  - [Environment Configuration (`.env`)](#environment-configuration-env)
- [Middleware & Helper Functions](#middleware--helper-functions)
- [API Endpoints](#api-endpoints)
- [Database Structure](#database-structure)
- [License](#license)
- [Contact & Support](#contact--support)

---

## 🚀 Features

- **Session Management** with Flask-Session
- **Role-Based Access Control** via decorators
- **Two-Factor Authentication (2FA)** with `pyotp`
- **Google reCAPTCHA v2 Integration**
- **PostgreSQL Integration** with connection pooling
- **Environment-based Configuration**
- **Secure Cookie & Token Management**
- **Production-Ready APIs** for authentication & administration

---

## ⚡ Quickstart

```bash
pip install mbkauthe
```

```python
from flask import Flask
from mbkauthe import configure_mbkauthe

app = Flask(__name__)
configure_mbkauthe(app)
```

---

## 🧰 Installation

1. **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    ```

2. **Install the package:**
    ```bash
    pip install mbkauthe
    ```

3. **Install dependencies manually (if needed):**
    ```bash
    pip install Flask Flask-Session psycopg2-binary python-dotenv bcrypt pyotp requests Flask-Cors SQLAlchemy
    ```

4. **Local development:**
    ```bash
    pip install -e .
    ```

---

## 🧑‍💻 Usage

### Basic Setup

```python
from flask import Flask, session
from dotenv import load_dotenv
from mbkauthe import configure_mbkauthe, validate_session

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-flask-secret-key'

configure_mbkauthe(app)

@app.route('/')
def home():
    return "Welcome!"

@app.route('/dashboard')
@validate_session
def dashboard():
    return f"Hello {session['user']['username']}!"

if __name__ == '__main__':
    app.run(debug=True)
```

---

### Environment Configuration (`.env`)

```dotenv
FLASK_SECRET_KEY='flask-secret'
mbkautheVar='{
    "APP_NAME": "MyApp",
    "RECAPTCHA_SECRET_KEY": "your-recaptcha-key",
    "RECAPTCHA_Enabled": "false",
    "BypassUsers": ["admin"],
    "SESSION_SECRET_KEY": "your-session-secret",
    "IS_DEPLOYED": "false",
    "LOGIN_DB": "postgresql://user:pass@host:5432/db",
    "MBKAUTH_TWO_FA_ENABLE": "false",
    "COOKIE_EXPIRE_TIME": "7",
    "DOMAIN": "localhost",
    "Main_SECRET_TOKEN": "your-api-token",
    "SESSION_TYPE": "filesystem",
    "SESSION_SQLALCHEMY_TABLE": "session",
    "SESSION_SQLALCHEMY": null,
    "EncryptedPassword": "false"
}'
```

---

## 🔐 Middleware & Helper Functions

### `@validate_session`
Checks for valid session and access to the app.

```python
@app.route('/dashboard')
@validate_session
def dashboard():
    return "Welcome!"
```

### `@check_role_permission('SuperAdmin')`
Checks if user has the required role.

### `@validate_session_and_role('Any')`
Combines session and role validation.

### `@authenticate_token`
Protects routes using a static token.

```python
@app.route('/api/internal')
@authenticate_token
def internal_api():
    return {"message": "Authenticated!"}
```

### `get_user_data(username, parameters)`
Fetches user data from DB.

---

## 📡 API Endpoints

| Endpoint                        | Method | Description                     |
| ------------------------------ | ------ | ------------------------------- |
| `/mbkauthe/api/login`          | POST   | User login                      |
| `/mbkauthe/api/logout`         | POST   | Logout current user             |
| `/mbkauthe/api/terminateAllSessions` | POST | Terminate all sessions (admin) |
| `/mbkauthe/package`            | GET    | Package metadata                |
| `/mbkauthe/version`            | GET    | Package version                 |
| `/mbkauthe/package-lock`       | GET    | Dependency metadata             |

---

## 🧱 Database Structure

### Required Tables

#### `Users` (Core user data)
```sql
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    UserName TEXT UNIQUE NOT NULL,
    Password TEXT NOT NULL,
    Role TEXT,
    SessionId TEXT,
    Active BOOLEAN DEFAULT TRUE,
    AllowedApps TEXT[]
);
```

#### `TwoFA` (2FA secrets)
#### `session` (If using SQLAlchemy session store)
#### `profiledata` (User profile fields)

---

### 🔐 Password Storage

Set `"EncryptedPassword": "true"` in `.env` to use **bcrypt** hashes.

To generate a bcrypt hash:

```python
import bcrypt
bcrypt.hashpw(b"your_password", bcrypt.gensalt()).decode()
```

---

## 📄 License

This project is licensed under the [Mozilla Public License 2.0](https://opensource.org/licenses/MPL-2.0).

---

## 📬 Contact & Support

Created by **Maaz Waheed**  
GitHub: [@42Wor](https://github.com/42Wor)

---
