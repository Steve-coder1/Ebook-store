# Ebook Store - Systems 1, 2, 3, 4, 5 & 6

Flask backend implementing:
- **System 1**: authentication (users/admin), sessions, password reset, login protections.
- **System 2**: ebook content engine (categories, ebooks, files, versions, favorites, preview, secure downloads).
- **System 3**: code-key gatekeeper (single-use code generation, validation, expiry, usage logging, and brute-force controls).
- **System 4**: controlled secure download delivery sessions (temporary links, multi-file handling, and delivery analytics).
- **System 5**: reviews and ratings engine with anti-abuse controls and analytics.
- **System 6**: favorites and user-profile personalization with download history.

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
- Admin failure-rate alert endpoint for spike detection (`/admin/download-failure-alerts`)

### Reviews & Ratings (System 5)
- Reviews table (`reviews`) with one review per user per ebook, rating (1-5), review text, timestamps
- Review submission endpoint with login requirement and duplicate prevention
- Review editing by the same user and admin deletion controls
- Rating aggregation automatically included in ebook payloads (`average_rating`, `review_count`) for listings/details/home-style sections
- Anti-abuse controls with review attempt rate-limiting and suspicious attempt logging (`review_attempt_logs`)
- User profile integration endpoint to list user-posted reviews with linked ebook titles (`/profile/reviews`)
- Admin analytics endpoint (`/admin/reviews/analytics`) for most reviewed, highest rated, and recent review activity

### Favorites & User Profile (System 6)
- Favorites add/remove/list endpoints for authenticated users
- Favorites listing supports sorting by:
  - `recent` (default)
  - `rating`
  - `title`
- Dedicated download history table (`download_history`) storing:
  - user
  - ebook
  - code used (if any)
  - timestamp
  - version label downloaded
- User-only history endpoint (`/downloads/history`) enforces ownership
- Admin history visibility endpoint (`/admin/download-histories`) supports user/ebook filtering
- Download history entries are recorded after successful authenticated and code-based downloads

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
- `reviews`
- `review_attempt_logs`
- `download_history`

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
- Review endpoints enforce per-user uniqueness and submission rate limits.
- Download history endpoints are scoped: users can only read their own history; admins can query aggregate history.
- Set `SESSION_COOKIE_SECURE=true` in HTTPS deployments.
- Configure a stable production `SECRET_KEY` and integrate a real email provider for password reset delivery.
