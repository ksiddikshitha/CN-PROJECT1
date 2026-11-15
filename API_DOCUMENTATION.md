# API and Route Documentation

Mutations require a valid Flask-WTF CSRF token. Authenticated routes require a Flask-Login session unless marked Public. Upload sizes are bounded by MAX_CONTENT_LENGTH_MB. File/folder identifiers are always checked against the current owner or recipient on the server.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | / | Public | Landing page |
| GET, POST | /register | Public | Register: name, email, password, confirm |
| GET, POST | /login | Public | Sign in |
| GET, POST | /forgot-password | Public | Request a generic-response reset |
| GET, POST | /reset/{token} | Token | Validate one-use token and set new password |
| POST | /logout | Required | End session |
| GET | /dashboard | Required | Actual file, quota, chart and activity data |
| GET | /files?q=&type= | Required | List/search/filter owned files |
| POST | /upload | Required | Multipart files; optional folder_id |
| GET | /file/{id}/download | Owner | Integrity-check and download |
| GET | /file/{id}/preview | Owner | Inline preview |
| POST | /file/{id}/rename | Owner | Rename safe file name; preserves extension/content match |
| POST | /file/{id}/move | Owner | Move to owned folder_id or root |
| POST | /file/{id}/delete | Owner | Move to recycle bin |
| POST | /file/{id}/restore | Owner | Restore from recycle bin |
| POST | /file/{id}/purge | Owner | Permanently remove bytes and metadata |
| POST | /file/{id}/favorite | Owner | Toggle favourite |
| GET | /favorites | Required | List favourites |
| GET, POST | /folders | Required | Browse root/create nested folder |
| GET | /folders/{id} | Owner | Browse folder and its files |
| POST | /folder/{id}/rename | Owner | Rename folder |
| POST | /folder/{id}/move | Owner | Move folder; cycle checks enforced |
| POST | /folder/{id}/delete | Owner | Move empty folder to recycle bin |
| POST | /folder/{id}/restore | Owner | Restore folder |
| POST | /folder/{id}/purge | Owner | Permanently remove empty folder |
| GET | /trash | Required | List deleted files/folders |
| POST | /trash/empty | Required | Permanently remove trashed files and empty folders |
| POST | /share/{file_id} | Owner | Create public link and optionally grant a registered recipient by email |
| GET | /shared | Required | List links created by the current user |
| POST | /share/revoke/{id} | Link owner | Revoke link and recipient access |
| GET | /shared-with-me | Required | List active files granted to current account |
| GET, POST | /shared-with-me/{id} | Recipient | Open share; enter password if configured |
| GET | /shared-with-me/{id}/preview | Recipient | Inline preview under recipient authorization |
| GET | /shared-with-me/{id}/download | Recipient | Download if allowed and under limit |
| GET, POST | /s/{token} | Public share | Access public link; submit password if required |
| GET | /s/{token}?view=1 | Public share | Inline preview |
| GET | /s/{token}?download=1 | Public share | Download if allowed and under limit |
| GET | /activity | Required | Activity history |
| GET | /analytics | Required | Quota, file type distribution and largest files |
| GET | /network | Public | Architecture guide |
| GET | /api/network-events | Required | JSON application activity |
| GET, POST | /settings | Required | Update profile/password |

The share-creation form accepts recipient_email, password, days (1–365), limit (1–10000) and download checkbox. The raw high-entropy public token appears once in the owner's response; its SHA-256 digest is stored. Reset links are likewise random, one-use and stored only as hashes; when PASSWORD_RESET_LOG_LINKS=true, local reset links are emitted to the application log.

Network-event JSON contains method, endpoint, status, ISO timestamp, event and transfer_bytes. This reports application activity, not TCP packets.

