
# mbkauthe (Python/Flask Version)

<!-- [![PyPI version](https://badge.fury.io/py/mbkauthe.svg)](https://badge.fury.io/py/mbkauthe) -->

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Implementation in a Project](#implementation-in-a-project)
  - [Basic Setup](#basic-setup)
  - [Environment Variables (.env)](#environment-variables-env)
- [Middleware & Function Documentation](#middleware--function-documentation)
  - [`@validate_session`](#validate_session)
  - [`@check_role_permission(required_role)`](#check_role_permissionrequired_role)
  - [`@validate_session_and_role(required_role)`](#validate_session_and_rolerequired_role)
  - [`get_user_data(username, parameters)`](#get_user_datausername-parameters)
  - [`@authenticate_token`](#authenticate_token)
- [API Endpoints](#api-endpoints)
  - [Login](#login)
  - [Logout](#logout)
  - [Terminate All Sessions](#terminate-all-sessions)
  - [Package Information](#package-information)
  - [Version Information](#version-information)
  - [Package Lock Information](#package-lock-information)
- [Database Structure](#database-structure)
  - [Users Table](#users-table)
  - [Session Table](#session-table)
  - [Two-Factor Authentication (TwoFA) Table](#two-factor-authentication-twofa-table)
  - [Profile Data Table](#profile-data-table)
  - [Query to Add a User](#query-to-add-a-user)
  - [Important Note on Passwords](#important-note-on-passwords)
- [License](#license)
- [Contact & Support](#contact--support)

---

`mbkauthe` is a reusable authentication system for Python Flask applications, ported from the original Node.js version. It simplifies session management, user authentication, role-based access control, and database interaction. It integrates with PostgreSQL and supports features like optional Two-Factor Authentication (2FA) and reCAPTCHA verification.

## Features

- Secure session management with Flask-Session
- Role-based access control decorators
- Optional Two-Factor Authentication (2FA) with TOTP
- Google reCAPTCHA integration
- PostgreSQL connection pooling
- Cookie and session customization
- Supports plaintext or bcrypt-hashed passwords

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\activate  # Windows

pip install -r requirements.txt
# or manually:
# pip install Flask Flask-Session psycopg2-binary python-dotenv bcrypt requests pyotp Flask-Cors SQLAlchemy importlib-metadata Pillow Werkzeug toml
```

### Install mbkauthe

```bash
pip install -e ./mbkauthe
# or if published:
# pip install mbkauthe
```

## Usage

### Implementation in a Project

See `app.py` and `templates/` for a full usage demo.

### Basic Setup

```python
from flask import Flask, render_template, session
from mbkauthe import configure_mbkauthe, validate_session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

configure_mbkauthe(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/protected')
@validate_session
def protected():
    user = session.get('user')
    return f"Welcome, {user['username']}!"
```

### Environment Variables (.env)

```dotenv
FLASK_SECRET_KEY=your-flask-secret

mbkautheVar='{
  "APP_NAME": "YourApp",
  "RECAPTCHA_SECRET_KEY": "",
  "RECAPTCHA_Enabled": "false",
  "BypassUsers": ["admin"],
  "SESSION_SECRET_KEY": "long-secret",
  "IS_DEPLOYED": "false",
  "LOGIN_DB": "postgresql://user:pass@localhost:5432/db",
  "MBKAUTH_TWO_FA_ENABLE": "false",
  "COOKIE_EXPIRE_TIME": "7",
  "DOMAIN": "localhost",
  "Main_SECRET_TOKEN": "internal-token",
  "SESSION_TYPE": "sqlalchemy",
  "SESSION_SQLALCHEMY_TABLE": "session",
  "SESSION_SQLALCHEMY": null,
  "EncryptedPassword": "false"
}'
```

## Middleware & Function Documentation

### `@validate_session`

Protects routes with session checks.

```python
@validate_session
def dashboard():
    user = session['user']
    return f"Welcome {user['username']}"
```

### `@check_role_permission(required_role)`

Restricts routes based on user role.

```python
@validate_session
@check_role_permission("SuperAdmin")
def admin_panel():
    return "Admin Panel"
```

### `@validate_session_and_role(required_role)`

Combines session and role validation.

```python
@validate_session_and_role("SuperAdmin")
def secured_admin():
    return "Secured Area"
```

### `get_user_data(username, parameters)`

Retrieves user data.

```python
data = get_user_data("johndoe", ["FullName", "email"])
```

### `@authenticate_token`

Secures internal APIs via token header.

```python
@authenticate_token
def terminate_sessions():
    return {"success": True}
```

## API Endpoints

All routes are prefixed with `/mbkauthe`.

### Login

**POST** `/mbkauthe/api/login`

```json
{
  "username": "user",
  "password": "pass"
}
```

### Logout

**POST** `/mbkauthe/api/logout`

Clears session cookie.

### Terminate All Sessions

**POST** `/mbkauthe/api/terminateAllSessions`

Header:

```
Authorization: <Main_SECRET_TOKEN>
```

### Package Information

**GET** `/mbkauthe/package`

Returns metadata.

### Version Information

**GET** `/mbkauthe/version`

Returns version info.

### Package Lock Information

**GET** `/mbkauthe/package-lock`

Attempts to return package dependencies.

## Database Structure

### Users Table

```sql
CREATE TABLE "Users" (
  id SERIAL PRIMARY KEY,
  "UserName" TEXT UNIQUE NOT NULL,
  "Password" TEXT NOT NULL,
  "Role" TEXT NOT NULL DEFAULT 'NormalUser',
  "Active" BOOLEAN DEFAULT true,
  "HaveMailAccount" BOOLEAN DEFAULT false,
  "SessionId" TEXT,
  "GuestRole" JSONB,
  "AllowedApps" JSONB
);
```

### Session Table (SQLAlchemy)

```sql
CREATE TABLE session (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) UNIQUE NOT NULL,
  data TEXT,
  expiry TIMESTAMPTZ NOT NULL
);
```

### Session Table (Custom)

```sql
CREATE TABLE session (
  sid VARCHAR PRIMARY KEY,
  sess JSON NOT NULL,
  expire TIMESTAMPTZ NOT NULL
);
```

### Two-Factor Authentication (TwoFA) Table

```sql
CREATE TABLE "TwoFA" (
  "UserName" TEXT PRIMARY KEY REFERENCES "Users"("UserName") ON DELETE CASCADE,
  "TwoFAStatus" BOOLEAN DEFAULT false,
  "TwoFASecret" TEXT NOT NULL
);
```

### Profile Data Table

```sql
CREATE TABLE profiledata (
  "UserName" TEXT PRIMARY KEY REFERENCES "Users"("UserName") ON DELETE CASCADE,
  "FullName" TEXT,
  "email" TEXT,
  "Image" TEXT,
  "ProjectLinks" JSONB,
  "SocialAccounts" JSONB,
  "Bio" TEXT,
  "Positions" JSONB
);
```

### Query to Add a User

```sql
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "AllowedApps")
VALUES ('admin', 'plaintext_password', 'SuperAdmin', true, '["YourApp"]');

-- With bcrypt hash
INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "AllowedApps")
VALUES ('admin', '$2b$12$hash...', 'SuperAdmin', true, '["YourApp"]');
```

## Important Note on Passwords

- `"EncryptedPassword": "true"` → use bcrypt
- `"EncryptedPassword": "false"` → use plaintext
- Use `bcrypt.hashpw()` to hash passwords if needed

## License

This project is licensed under the **Mozilla Public License 2.0**.

## 📬 Contact & Support

- GitHub: [https://github.com/42Wor/mbkauthepy](https://github.com/42Wor/mbkauthepy)
- Maintainer: **Maaz Waheed**
```

Let me know if you want this turned into a downloadable file or structured as documentation for GitHub Pages or a static site generator!