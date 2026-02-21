# Ebook Store - Systems 1 & 2 (Auth + Ebook Management)

Flask-based backend implementing:
- **System 1**: authentication (users/admin), sessions, password reset, login protections.
- **System 2**: ebook content engine (categories, ebooks, files, versions, favorites, preview, secure downloads, admin content controls).

## Implemented capabilities

### Identity (System 1)
- User register/login/logout (email/password)
- Password hashing via Werkzeug
- Password reset token flow
- Profile email/password change
- Multi-device sessions (`sessions` table)
- Session inactivity expiry + logout invalidation
- Captcha challenge on login (development arithmetic challenge)
- Login rate limiting / brute-force protection (`login_attempts`)
- Separate admin login route
- Admin password strength requirement
- Admin login audit logs (`audit_logs`)

### Ebook Management (System 2)
- Category management (`categories`)
- Ebook records with metadata (`ebooks`)
- Multi-file/version support (`ebook_files`)
- Secure server-side private storage (outside static/public root)
- Preview support (`summary_text`, optional preview file, bundle file list preview)
- Favorites (`favorites`)
- Temporary signed download links with expiry
- Backend-validated file downloads only (no direct public URLs)
- Download event tracking + admin download counts (`download_events`)
- Admin controls: create/update/deactivate/delete ebooks, upload files, upload preview files, set featured flag

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

## Important storage & security notes
- Ebook and preview files are stored in `PRIVATE_STORAGE_ROOT` (default `./private_storage`) and are **not** served as static files.
- Downloads are gated by auth and signed short-lived tokens (`/ebooks/<ebook_id>/download-link/<file_id>` -> `/download/<token>`).
- Set `SESSION_COOKIE_SECURE=true` in HTTPS deployments.
- Configure a stable production `SECRET_KEY` and integrate a real email provider for password reset delivery.
