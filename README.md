# Ebook Store - Systems 1, 2, 3 & 4

Flask backend implementing:
- **System 1**: authentication (users/admin), sessions, password reset, login protections.
- **System 2**: ebook content engine (categories, ebooks, files, versions, favorites, preview, secure downloads).
- **System 3**: code-key gatekeeper (single-use code generation, validation, expiry, usage logging, and brute-force controls).
- **System 4**: controlled secure download delivery sessions (temporary links, multi-file handling, and delivery analytics).

## Implemented capabilities

### Identity (System 1)
- User register/login/logout (email/password)
- Password hashing via Werkzeug
- Password reset token flow
- Profile email/password change
- Multi-device sessions (`sessions` table)
- Session inactivity expiry + logout invalidation
- Captcha challenge on login
- Login rate limiting / brute-force protection (`login_attempts`)
- Separate admin login route
- Admin password strength requirement
- Admin login audit logs (`audit_logs`)

### Ebook Management (System 2)
- Category management (`categories`)
- Ebook records with metadata (`ebooks`)
- Multi-file/version support (`ebook_files`)
- Secure server-side private storage outside static/public root
- Preview support (`summary_text`, optional preview file, bundle file list preview)
- Favorites (`favorites`)
- Temporary signed download links
- Backend-validated file downloads only (no direct public URLs)
- Download event tracking + admin download counts (`download_events`)
- Admin controls for create/update/deactivate/delete and upload operations

### Code Key Gatekeeper (System 3)
- System-generated high-entropy alphanumeric code generation
- Code model (`codes`) with single-use, expiry, ebook linkage, and admin creator tracking
- Code usage model (`code_usage_logs`) with user (nullable), IP, device, usage timestamp, download completion state, and failure reason
- Code brute-force model (`code_attempts`) for failed-attempt tracking
- Code validation flow with existence, expiration, single-use, and deactivation checks
- Rate-limit checks (IP + session) with optional captcha requirement after repeated failures
- Admin controls to generate/deactivate/list codes and inspect usage + failures

### Secure Download Delivery (System 4)
- Download session model (`download_sessions`) created after successful code validation
- Session links code + ebook + user(optional) + IP + device metadata + auto expiry window
- File links are signed short-lived tokens tied to download session + file + one-time token JTI
- One-time token use ledger (`download_token_uses`) prevents link reuse
- Multi-file handling:
  - per-file secure links in validation response
  - optional bundle ZIP endpoint with expiring link (`/download/code/bundle/<token>`)
- Attempt/result tracking (`download_attempt_logs`) with success/failure reason and completion status
- Download history endpoint for authenticated users (`/downloads/history`)
- Admin failure-rate alert endpoint for spike detection (`/admin/download-failure-alerts`)

## Database tables
- `users`
- `password_reset_tokens`
- `sessions`
- `login_attempts`
- `audit_logs`
- `categories`
- `ebooks`
- `ebook_files`
- `favorites`
- `download_events`
- `codes`
- `code_usage_logs`
- `code_attempts`
- `download_sessions`
- `download_attempt_logs`
- `download_token_uses`

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open:
- `http://localhost:5000/` user auth page
- `http://localhost:5000/admin` admin login page

## Security notes
- Ebook and preview files are stored in `PRIVATE_STORAGE_ROOT` (default `./private_storage`) and are not served as static files.
- User-auth downloads use signed short-lived tokens (`/ebooks/<ebook_id>/download-link/<file_id>` -> `/download/<token>`).
- Code-validation returns session-scoped file links and optional bundle links (`/download/code/<token>`, `/download/code/bundle/<token>`).
- Set `SESSION_COOKIE_SECURE=true` in HTTPS deployments.
- Configure a stable production `SECRET_KEY` and integrate a real email provider for password reset delivery.
