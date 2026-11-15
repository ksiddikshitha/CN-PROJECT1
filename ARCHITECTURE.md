# CloudLock Architecture

## Request, identity and storage flow
    Browser → HTTP/HTTPS request → Flask route
    → CSRF/session/rate-limit checks
    → current account, owner or recipient-grant authorization
    → SQLAlchemy metadata in SQLite
    → local filesystem or authenticated Supabase private bucket
    → response to browser

Local development uses HTTP; deployment should terminate HTTPS. TCP/IP transports these requests. Flask-Login identifies the session, CSRF protects state changes, and route handlers check ownership or recipient grants before touching metadata or bytes. The app sends cloud object requests from the server, never from frontend JavaScript.

## File operations
Uploads use multipart/form-data and XHR reports bytes sent. Flask checks the allowlisted extension and common file signatures, validates quota, computes SHA-256, rejects same-owner duplicates, creates an opaque storage key, stores bytes and then metadata. Downloads require owner/recipient/public-token authorization and a valid permission/expiry/limit. The provider reads object bytes, CloudLock verifies SHA-256, and only then returns content. Rename and move affect metadata while preserving object keys. Trash is reversible; purge deletes object bytes and metadata.

## Folder model
Folders form a self-referencing tree owned by one user. Browsing filters both folders and files by owner. Folder moves validate ownership and walk ancestors to prevent cycles. Files may be assigned to an owned folder or root. Empty folders can be soft-deleted and restored.

## Sharing and reset
A public share contains a high-entropy random URL token; the database stores its SHA-256 hash. Optional password hashes, expiry, download cap, permission and revocation are checked on each request. A registered recipient grant stores recipient_id and appears in that account's Shared With Me inbox; downloads/previews authorize the current recipient separately from public-token access. Revocation disables both access paths immediately.

Password recovery stores a hash of a cryptographically random token, one-use time and expiry. Local development can log a recovery URL only when PASSWORD_RESET_LOG_LINKS=true. Production email delivery is intentionally not claimed; reset-link logging should be disabled in production.

## Database
- User owns files, folders, shares and activity.
- File stores owner, optional folder, safe display name, MIME guess, byte count, digest, opaque key, favourite and trash timestamps.
- Folder stores owner, optional parent and trash timestamp.
- ShareLink stores file/owner, optional recipient, token hash, optional password hash, permission, expiry, count/limit and revocation.
- PasswordResetToken stores user, hashed token, expiry and used timestamp.
- ActivityLog, Favourite and Notification store application events and related state.

Startup uses SQLAlchemy create_all plus an additive upgrade for recipient_id and folder.deleted_at on earlier project databases. New schema changes should be migrated with Alembic after backing up the database.

## Security boundaries
Werkzeug password hashes; random share/reset tokens stored as hashes; CSRF; rate limits; server-side ownership and recipient checks; safe filenames; opaque storage keys; extension and signature checks; quota/request-size bounds; digest verification; private Supabase bucket verification; HttpOnly and SameSite cookie defaults. Production should use HTTPS, a stable high-entropy secret, secure cookies, dedicated rate-limit storage, least privilege and backups.

## Network demonstration
The Network page explains client-server and request-response flows. Authenticated /api/network-events reports application-level methods, endpoints, statuses, timestamps and transfer sizes. It does not capture network packets or show raw TCP/IP frames.

