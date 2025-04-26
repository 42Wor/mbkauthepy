## Database structure

[<- Back](README.md)

## Table of Contents

1. [Users Table](#users-table)
2. [Session Table](#session-table)
3. [Two-Factor Authentication Table](#two-factor-authentication-table)
4. [Query to Add a User](#query-to-add-a-user)


### Users Table

- **Columns:**

  - `id` (INTEGER, auto-increment, primary key): Unique identifier for each user.
  - `UserName` (TEXT): The username of the user.
  - `Password` (TEXT): The hashed password of the user.
  - `Role` (ENUM): The role of the user. Possible values: `SuperAdmin`, `NormalUser`, `Guest`.
  - `Active` (BOOLEAN): Indicates whether the user account is active.
  - `HaveMailAccount` (BOOLEAN)(optional): Indicates if the user has a linked mail account.
  - `SessionId` (TEXT): The session ID associated with the user.
  - `GuestRole` (JSONB): Stores additional guest-specific role information in binary JSON format.
  - `AllowedApps`(JSONB): 

- **Schema:**
  ```sql
  CREATE TABLE "Users" (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      "UserName" TEXT NOT NULL,
      "Password" TEXT NOT NULL,
      "Role" TEXT CHECK("Role" IN ('SuperAdmin', 'NormalUser', 'Guest')) NOT NULL DEFAULT 'NormalUser'::text,
      "Active" BOOLEAN NOT NULL DEFAULT true,
      "HaveMailAccount" BOOLEAN NOT NULL DEFAULT false,
      "SessionId" TEXT,
      "GuestRole" JSONB DEFAULT '{"allowPages": [""], "NotallowPages": [""]}'::jsonb
      "AllowedApps" JSONB DEFAULT '["mbkauthe"]'::jsonb
  );
  ```

### Session Table

- **Columns:**

  - `sid` (VARCHAR, primary key): Unique session identifier.
  - `sess` (JSON): Session data stored in JSON format.
  - `expire` (TIMESTAMP): Expiration timestamp for the session.

- **Schema:**
  ```sql
  CREATE TABLE session (
          sid VARCHAR PRIMARY KEY,
          sess JSON NOT NULL,
          expire TIMESTAMP NOT NULL
  );
  ```

### Two-Factor Authentication Table

- **Columns:**

  - `UserName` (TEXT): The username of the user.
  - `TwoFAStatus` (TEXT): The status of two-factor authentication (e.g., enabled, disabled).
  - `TwoFASecret` (TEXT): The secret key used for two-factor authentication.

- **Schema:**
  ```sql
  CREATE TABLE "TwoFA" (
          "UserName" TEXT NOT NULL PRIMARY KEY,
          "TwoFAStatus" TEXT NOT NULL DEFAULT false,
          "TwoFASecret" TEXT NOT NULL
  );
  ```

### Query to Add a User

To add new users to the `Users` table, use the following SQL queries:

```sql
        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('support', '12345678', 'SuperAdmin', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);

        INSERT INTO "Users" ("UserName", "Password", "Role", "Active", "HaveMailAccount", "SessionId", "GuestRole")
        VALUES ('test', '12345678', 'NormalUser', true, false, NULL, '{"allowPages": [""], "NotallowPages": [""]}'::jsonb);
```

- Replace `support` and `test` with the desired usernames.
- Replace `12345678` with the actual passwords.
- Adjust the `Role` values as needed (`SuperAdmin`, `NormalUser`, or `Guest`).
- Modify the `Active` and `HaveMailAccount` values as required.
- Update the `GuestRole` JSON object if specific permissions are required(this functionality is under construction).