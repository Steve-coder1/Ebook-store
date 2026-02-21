# Ebook Store - Systems 1 through 9

Backend: Flask + SQLAlchemy.

## System 9: Security, Monitoring & Automation

### Transport security
- HTTPS enforcement support via `FORCE_HTTPS=true`.
- HSTS + secure response headers are added globally.
- Secure cookies remain enabled (`SESSION_COOKIE_SECURE`).

### Rate limiting & abuse controls
- Login rate limit (existing) with security-event logging.
- Code entry rate limit (existing) with security-event logging.
- Review submission rate limit (existing) with security-event logging.
- Password-reset request rate limiting added (`password_reset_attempts`).

### Bot/abuse visibility
- Security events table (`security_events`) for suspicious patterns and cooldown events.
- Admin endpoint: `GET /admin/security-events`.

### Error logging & monitoring
- Error logs retained in `error_logs`.
- Failed downloads tracked by `download_attempt_logs`.
- Admin failure-rate alert endpoint retained: `GET /admin/download-failure-alerts`.

### Automated backups
- Manual backup trigger retained: `POST /admin/backups/trigger`.
- Backup schedule setting endpoint added: `POST /admin/backups/schedule` (`daily|weekly`).

### Automated cleanup
- Cleanup endpoint added: `POST /admin/automation/cleanup`.
- Removes expired unused codes and purges old logs/attempt tables using retention window (`SECURITY_LOG_RETENTION_DAYS`, default 90).

### Maintenance mode controls
- Granular maintenance toggles:
  - `enabled`
  - `disable_downloads`
  - `disable_code_entry`
  - `lockdown`
  - custom `message`
- Endpoint: `POST /admin/maintenance/toggle`.
- All maintenance actions logged to `audit_logs`.

### Staging support
- Env-level staging lock: `ENABLE_STAGING_MODE=true`.
- Runtime staging toggle endpoints:
  - `GET /admin/staging`
  - `POST /admin/staging/toggle`

## New tables for System 9
- `password_reset_attempts`
- `security_events`

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
