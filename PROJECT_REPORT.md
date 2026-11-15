# CloudLock — Computer Networks Project Report

## 1. Abstract
CloudLock is a Flask file management and controlled sharing application. It demonstrates client-server communication, HTTP request-response behavior, authentication, authorization, storage abstraction, cloud object storage integration and content integrity checks.

## 2. Introduction
Web applications move files between browsers, application servers, databases and object stores. CloudLock makes these components visible through an academic-scale implementation with local development storage and an optional Supabase Storage adapter.

## 3. Problem statement
Users need a single organized place to store and share files while controlling ownership, recipient access, expiration and download capability. A teaching project should expose the network and security mechanisms supporting the workflow.

## 4. Objectives
Implement registration and sessions; private upload/download; organize and search; controlled links; integrity checks; activity history; network architecture explanation; and local-first storage.

## 5. Existing system
Basic local transfer and public links can provide limited ownership visibility, integrity information or expiry controls. CloudLock adds application-side checks and a visible activity trail. This is a general comparison, not a measured product evaluation.

## 6. Proposed system
A browser communicates with Flask. Flask authenticates the session, checks ownership/share state, stores metadata with SQLAlchemy/SQLite, and accesses bytes through local or Supabase storage. HTTP responses deliver pages and authorized content.

## 7. Requirements
Hardware: ordinary networked laptop/desktop. Software: Python 3.11+, browser and pip; optional Supabase project. Local execution needs no external storage credentials.

## 8. System architecture
See ARCHITECTURE.md for architecture and request flow. Production traffic should use HTTPS. TCP/IP is the transport stack; application logs do not expose packets.

## 9. Modules
Authentication; file upload/metadata; folders/favourites/trash; share links; storage abstraction; activity and network demonstration; analytics; account settings.

## 10. Database design
Tables: User, File, Folder, ShareLink, ActivityLog, Favourite and Notification. Foreign keys associate data with accounts. Email, storage key and share token hash are unique. SQLite initializes through SQLAlchemy.

## 11. Implementation
Flask routes/templates, SQLAlchemy models, Flask-Login, Flask-WTF CSRF, Flask-Limiter and storage providers. Local files use opaque random keys. Supabase operations are server-side and use environment configuration.

## 12. Computer Networks concepts
Client-server architecture; HTTP request-response; multipart transfer; TCP/IP as HTTP transport; cloud object storage; application-layer authentication/authorization; request metadata; checksum integrity.

## 13. Security mechanisms
Werkzeug password hashes, authenticated sessions, CSRF, rate limits, server-side ownership checks, opaque storage IDs, file extension/size/quota checks, random share tokens stored as hashes, password/expiry/limit/revocation, and SHA-256 verification before downloads.

## 14. Testing
Automated coverage includes account lifecycle, authorization, upload integrity and content validation, file/folder rename and moves, nested browsing and cycle rejection, recycle-bin restoration/permanent deletion, public and account-to-account sharing, reset token single-use, CSRF, dashboard metrics and a mocked Supabase REST contract. Latest result: 15 tests passed.

## 15. Results
Local server startup completed and GET / and GET /login both returned HTTP 200 at http://127.0.0.1:5000. The automated suite passed 15 tests. Workflows cover account-to-account inbox shares, password-reset token redemption, folder navigation, file transfer, trash, and analytics. Supabase was verified with mocked HTTP only, not live credentials.

## 16. Limitations
Password reset writes a short-lived link to the server log only when PASSWORD_RESET_LOG_LINKS=true; production email delivery is not integrated. Uploads are not resumable, there is no malware scanner or packet capture, and the Supabase adapter has not been tested against a live project. Database changes use a small additive startup migration; there is no Alembic revision history.

## 17. Future scope
Add Alembic migrations, PostgreSQL deployment, resumable upload, malware scanning, production email delivery, retention policies and operational monitoring.

## 18. Conclusion
CloudLock provides a local-first implementation for demonstrating a secure file workflow and the computer-network concepts behind it. Production use needs deployment hardening and operational controls.

## 19. References
Flask documentation; Flask-SQLAlchemy; Flask-Login; Flask-WTF; Werkzeug security; Supabase Storage; NIST Secure Hash Standard (SHA-256).

