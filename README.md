# PINK CLOUD
**Your Files. Your Space. Your Security.** A local-first file management and sharing system for a Computer Networks project.

## Features
- Flask registration/login, hashed passwords, CSRF-protected forms, secure session cookies and rate limits.
- Multiple file uploads with XHR byte progress, extension and file-signature checks, request/quota limits, same-user SHA-256 duplicate detection and digest verification on every read.
- File preview/download, rename, search, category filtering, favourites, moving between nested folders, folder create/rename/move/browse, soft-delete/restore and permanent deletion.
- Recycle-bin per-item restore/permanent deletion and empty-trash action. Permanent deletion removes metadata and bytes from the configured provider.
- User-to-user shares by registered email, Shared With Me inbox, owner share list and revoke. Public share URLs have random bearer tokens (only token hashes persist), optional password, expiry, download cap and download permission.
- Password reset with one-use, hashed, 30-minute tokens. In local development, set PASSWORD_RESET_LOG_LINKS=true to write one-time reset URLs to the Flask server log; no email delivery is claimed. Disable this option in production and connect a mail provider.
- Database-backed dashboard with actual file-type distribution, quota chart, largest files and activity.
- Local filesystem and server-side Supabase Storage adapters. Supabase requires a verified private bucket.
- Network architecture explanation and authenticated application-level event log.
- Responsive UI with light/dark mode.

## Stack and requirements
Python 3.11+ recommended; Flask, SQLAlchemy, Flask-Login, Flask-WTF, Flask-Limiter, SQLite, HTML, CSS and JavaScript. Internet access is required for package installation.

## Install and run (PowerShell)
    cd "C:\Users\siddi\OneDrive\Desktop\CN PROJECT1"
    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    Copy-Item .env.example .env
    python -c "import secrets; print(secrets.token_hex(32))"
    # Replace SECRET_KEY in .env with the generated value
    python run.py
Open http://127.0.0.1:5000. The app initializes SQLite and local storage automatically. If SECRET_KEY is omitted, a random key is generated at process start; sessions will end after a restart.

## Configuration
See .env.example. Local storage is the default. MAX_CONTENT_LENGTH_MB limits a request and USER_QUOTA_MB sets a user's stored-file quota. In production use a stable random SECRET_KEY, HTTPS, COOKIE_SECURE=true, a production WSGI server, a persistent rate-limit backend and backups. Set PASSWORD_RESET_LOG_LINKS=false in production so reset tokens are never written to logs.

### Supabase Storage
1. Create a private Storage bucket.
2. Set STORAGE_BACKEND=supabase, SUPABASE_URL, SUPABASE_KEY and SUPABASE_BUCKET in the server environment.
3. Use a server-only key with permission to inspect the bucket and upload/read/delete objects. A service-role key may be required by project policies. Never put it in frontend code or source control.
4. At startup CloudLock queries Supabase to verify that the configured bucket exists and is private. A failed verification stops startup rather than labeling an unverified provider as active. Missing credentials fall back to local mode.
5. App object requests use authenticated server-side Storage REST calls. Supabase integration was validated with mocked HTTP contract tests, not with a live project; supply credentials to verify your account/policies.

## Database
SQLite is initialized from SQLAlchemy models. On startup an additive migration adds recipient-sharing and folder-trash fields to existing CloudLock databases. For future schema changes, use reviewed Alembic/Flask-Migrate revisions and back up first. Do not remove instance/cloudvault.db to upgrade it: that would erase accounts and metadata.

## Tests
    python -m pytest -q
The suite uses temporary databases/storage and includes sharing, reset-token, folder, trash, integrity, CSRF, and mocked Supabase tests.

## Screenshots checklist
Capture landing, registration/login, dashboard with charts, upload progress, nested folders, file management, recipient inbox, password reset, analytics and Network Architecture & Security. Capture from the running app rather than presenting mockups as deployed output.

## Troubleshooting
- Missing module: activate the virtual environment and rerun pip install.
- Upload rejected: check extension, file signature, request size and remaining quota.
- Password reset: in local mode, inspect the Flask server log for the one-time URL; production needs a mail-delivery integration.
- Supabase startup failure: verify URL/key, bucket spelling, private bucket visibility and permissions. Local mode works without credentials.
- CSRF error: submit state-changing forms from the app so the token is included.

## Remaining limits
The reset delivery is development-log only; production email is not integrated. Supabase was not tested against a real account. Uploads are buffered in server memory within the configured request limit and are not resumable. Supported formats are deliberately limited; content signatures are checked for common binary types and UTF-8 text, but this is not malware scanning. Activity is application-level, not packet capture. No file version history, external recipient email invitations, antivirus scanning or Alembic revision history is included.

