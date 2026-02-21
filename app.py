import csv
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, jsonify, make_response, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    two_fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    device_info = db.Column(db.String(512), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    last_activity_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    successful = db.Column(db.Boolean, nullable=False, default=False)


class PasswordResetAttempt(db.Model):
    __tablename__ = "password_reset_attempts"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    device_info = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    slug = db.Column(db.String(140), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class Ebook(db.Model):
    __tablename__ = "ebooks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    summary_text = db.Column(db.Text, nullable=True)
    author = db.Column(db.String(255), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=True)
    cover_image_path = db.Column(db.String(500), nullable=True)
    slug = db.Column(db.String(280), nullable=True, unique=True, index=True)
    keywords = db.Column(db.Text, nullable=True)
    preview_file_path = db.Column(db.String(500), nullable=True)
    is_featured = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class EbookFile(db.Model):
    __tablename__ = "ebook_files"

    id = db.Column(db.Integer, primary_key=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False, unique=True)
    file_size = db.Column(db.BigInteger, nullable=False)
    version_label = db.Column(db.String(100), nullable=False, default="v1.0")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class Favorite(db.Model):
    __tablename__ = "favorites"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class DownloadEvent(db.Model):
    __tablename__ = "download_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    ebook_file_id = db.Column(db.Integer, db.ForeignKey("ebook_files.id"), nullable=False, index=True)
    downloaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class DownloadHistory(db.Model):
    __tablename__ = "download_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    code_id = db.Column(db.Integer, db.ForeignKey("codes.id"), nullable=True, index=True)
    downloaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    version_label = db.Column(db.String(100), nullable=True)


class DownloadSession(db.Model):
    __tablename__ = "download_sessions"

    id = db.Column(db.Integer, primary_key=True)
    code_id = db.Column(db.Integer, db.ForeignKey("codes.id"), nullable=False, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    device_info = db.Column(db.String(512), nullable=True)
    access_token = db.Column(db.String(255), nullable=False, unique=True, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class DownloadAttemptLog(db.Model):
    __tablename__ = "download_attempt_logs"

    id = db.Column(db.Integer, primary_key=True)
    download_session_id = db.Column(db.Integer, db.ForeignKey("download_sessions.id"), nullable=False, index=True)
    file_id = db.Column(db.Integer, db.ForeignKey("ebook_files.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    was_successful = db.Column(db.Boolean, nullable=False, default=False)
    download_completed = db.Column(db.Boolean, nullable=False, default=False)
    error_reason = db.Column(db.String(255), nullable=True)


class DownloadTokenUse(db.Model):
    __tablename__ = "download_token_uses"

    id = db.Column(db.Integer, primary_key=True)
    token_jti = db.Column(db.String(128), nullable=False, unique=True, index=True)
    download_session_id = db.Column(db.Integer, db.ForeignKey("download_sessions.id"), nullable=False, index=True)
    file_id = db.Column(db.Integer, db.ForeignKey("ebook_files.id"), nullable=True, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class AccessCode(db.Model):
    __tablename__ = "codes"

    id = db.Column(db.Integer, primary_key=True)
    code_value = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    created_by_admin = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class CodeUsageLog(db.Model):
    __tablename__ = "code_usage_logs"

    id = db.Column(db.Integer, primary_key=True)
    code_id = db.Column(db.Integer, db.ForeignKey("codes.id"), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    device_info = db.Column(db.String(512), nullable=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    download_completed = db.Column(db.Boolean, nullable=False, default=False)
    was_successful = db.Column(db.Boolean, nullable=False, default=False)
    failure_reason = db.Column(db.String(255), nullable=True)


class CodeAttempt(db.Model):
    __tablename__ = "code_attempts"

    id = db.Column(db.Integer, primary_key=True)
    session_key = db.Column(db.String(255), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    successful = db.Column(db.Boolean, nullable=False, default=False)


class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    review_text = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class ReviewAttemptLog(db.Model):
    __tablename__ = "review_attempt_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey("ebooks.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    was_successful = db.Column(db.Boolean, nullable=False, default=False)
    reason = db.Column(db.String(255), nullable=True)


class SiteSetting(db.Model):
    __tablename__ = "site_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), nullable=False, unique=True, index=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class SiteNotification(db.Model):
    __tablename__ = "site_notifications"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_by_admin = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class BackupJob(db.Model):
    __tablename__ = "backup_jobs"

    id = db.Column(db.Integer, primary_key=True)
    initiated_by_admin = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    backup_file = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="completed")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class ErrorLog(db.Model):
    __tablename__ = "error_logs"

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(120), nullable=False, default="system")
    severity = db.Column(db.String(20), nullable=False, default="error")
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class SearchQueryLog(db.Model):
    __tablename__ = "search_query_logs"

    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(255), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    result_count = db.Column(db.Integer, nullable=False, default=0)
    is_zero_result = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(120), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="warning")
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///ebook_store.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
    app.config["SESSION_IDLE_MINUTES"] = int(os.getenv("SESSION_IDLE_MINUTES", "30"))
    app.config["PASSWORD_RESET_TTL_MINUTES"] = int(os.getenv("PASSWORD_RESET_TTL_MINUTES", "15"))
    app.config["LOGIN_RATE_LIMIT_WINDOW_MINUTES"] = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15"))
    app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = int(os.getenv("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "5"))
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    app.config["DOWNLOAD_TOKEN_TTL_SECONDS"] = int(os.getenv("DOWNLOAD_TOKEN_TTL_SECONDS", "300"))
    app.config["CODE_TOKEN_TTL_SECONDS"] = int(os.getenv("CODE_TOKEN_TTL_SECONDS", "300"))
    app.config["CODE_ATTEMPT_WINDOW_MINUTES"] = int(os.getenv("CODE_ATTEMPT_WINDOW_MINUTES", "15"))
    app.config["CODE_ATTEMPT_MAX"] = int(os.getenv("CODE_ATTEMPT_MAX", "8"))
    app.config["CODE_CAPTCHA_THRESHOLD"] = int(os.getenv("CODE_CAPTCHA_THRESHOLD", "3"))
    app.config["DOWNLOAD_SESSION_TTL_MINUTES"] = int(os.getenv("DOWNLOAD_SESSION_TTL_MINUTES", "15"))
    app.config["REVIEW_RATE_LIMIT_WINDOW_MINUTES"] = int(os.getenv("REVIEW_RATE_LIMIT_WINDOW_MINUTES", "10"))
    app.config["REVIEW_RATE_LIMIT_MAX_ATTEMPTS"] = int(os.getenv("REVIEW_RATE_LIMIT_MAX_ATTEMPTS", "5"))
    app.config["PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES"] = int(os.getenv("PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES", "30"))
    app.config["PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS"] = int(os.getenv("PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS", "5"))
    app.config["SECURITY_LOG_RETENTION_DAYS"] = int(os.getenv("SECURITY_LOG_RETENTION_DAYS", "90"))
    app.config["FORCE_HTTPS"] = os.getenv("FORCE_HTTPS", "false").lower() == "true"
    app.config["ENABLE_STAGING_MODE"] = os.getenv("ENABLE_STAGING_MODE", "false").lower() == "true"

    project_root = Path(__file__).resolve().parent
    storage_root = Path(os.getenv("PRIVATE_STORAGE_ROOT", project_root / "private_storage")).resolve()
    files_root = storage_root / "ebooks"
    previews_root = storage_root / "previews"
    files_root.mkdir(parents=True, exist_ok=True)
    previews_root.mkdir(parents=True, exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    def set_setting(key, value):
        row = SiteSetting.query.filter_by(key=key).first()
        if not row:
            row = SiteSetting(key=key, value=str(value))
            db.session.add(row)
        else:
            row.value = str(value)
        db.session.commit()
        return row

    def get_setting(key, default=None):
        row = SiteSetting.query.filter_by(key=key).first()
        if not row:
            return default
        return row.value

    def log_admin_action(admin_id, action):
        db.session.add(
            AuditLog(
                admin_user_id=admin_id,
                action=action,
                ip_address=getattr(request, "remote_addr", None),
                device_info=getattr(request, "user_agent", None).string if getattr(request, "user_agent", None) else None,
            )
        )
        db.session.commit()

    def log_security_event(event_type, severity="warning", user_id=None, details=None):
        db.session.add(
            SecurityEvent(
                event_type=event_type,
                severity=severity,
                ip_address=(request.remote_addr or "unknown"),
                user_id=user_id,
                details=details,
            )
        )
        db.session.commit()

    @app.before_request
    def enforce_transport_and_maintenance_mode():
        if app.config["FORCE_HTTPS"] and not request.is_secure and not request.path.startswith("/health"):
            secure_url = request.url.replace("http://", "https://", 1)
            return make_response("", 301, {"Location": secure_url})

        if request.path.startswith("/static"):
            return None
        if request.path in ["/auth/login", "/admin/login", "/auth/captcha", "/codes/captcha"]:
            return None

        if app.config["ENABLE_STAGING_MODE"] or get_setting("staging_mode", "false").lower() == "true":
            return jsonify({"error": "Staging mode active", "staging": True}), 503

        if get_setting("maintenance_mode", "false").lower() != "true":
            return None

        active_session = get_session_from_cookie()
        if active_session:
            user = User.query.get(active_session.user_id)
            if user and user.role == "admin":
                return None

        disable_downloads = get_setting("maintenance_disable_downloads", "true").lower() == "true"
        disable_code_entry = get_setting("maintenance_disable_code_entry", "true").lower() == "true"
        lockdown = get_setting("maintenance_lockdown", "false").lower() == "true"

        path = request.path
        blocks_download = disable_downloads and (
            path.startswith("/download/")
            or path.startswith("/ebooks/") and "/download-link/" in path
        )
        blocks_codes = disable_code_entry and path == "/codes/validate"

        if not lockdown and not blocks_download and not blocks_codes:
            return None

        custom_message = get_setting("maintenance_message", "Maintenance in progress")
        response = {
            "error": "Maintenance mode enabled",
            "notification": get_setting("site_notification", ""),
            "message": custom_message,
            "disable_downloads": disable_downloads,
            "disable_code_entry": disable_code_entry,
            "lockdown": lockdown,
        }
        return jsonify(response), 503

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
        if request.is_secure or app.config["FORCE_HTTPS"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="ebook-download")
    code_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="code-download")

    def get_client_ip():
        forwarded = request.headers.get("X-Forwarded-For")
        return forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "unknown")

    def token_expiry(minutes):
        return utcnow() + timedelta(minutes=minutes)

    def generate_captcha_pair():
        a = secrets.randbelow(9) + 1
        b = secrets.randbelow(9) + 1
        return f"{a} + {b}", str(a + b)

    def issue_session(user):
        ttl = app.config["SESSION_IDLE_MINUTES"]
        token = secrets.token_urlsafe(48)
        session = Session(
            user_id=user.id,
            session_token=token,
            expires_at=token_expiry(ttl),
            device_info=request.user_agent.string,
            ip_address=get_client_ip(),
            last_activity_at=utcnow(),
        )
        db.session.add(session)
        db.session.commit()
        return token

    def login_blocked(email):
        window_start = utcnow() - timedelta(minutes=app.config["LOGIN_RATE_LIMIT_WINDOW_MINUTES"])
        attempts = LoginAttempt.query.filter(
            LoginAttempt.successful.is_(False),
            LoginAttempt.attempted_at >= window_start,
            (LoginAttempt.email == email) | (LoginAttempt.ip_address == get_client_ip()),
        ).count()
        return attempts >= app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"]

    def record_login_attempt(email, success):
        db.session.add(LoginAttempt(email=email, ip_address=get_client_ip(), successful=success))
        db.session.commit()

    def password_reset_rate_limited(email):
        window_start = utcnow() - timedelta(minutes=app.config["PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES"])
        attempts = PasswordResetAttempt.query.filter(
            PasswordResetAttempt.attempted_at >= window_start,
            (PasswordResetAttempt.email == email) | (PasswordResetAttempt.ip_address == get_client_ip()),
        ).count()
        return attempts >= app.config["PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS"]

    def record_password_reset_attempt(email):
        db.session.add(PasswordResetAttempt(email=email, ip_address=get_client_ip()))
        db.session.commit()

    def get_session_from_cookie():
        raw = request.cookies.get("session_token")
        if not raw:
            return None
        session = Session.query.filter_by(session_token=raw).first()
        if not session:
            return None
        if session.expires_at < utcnow():
            db.session.delete(session)
            db.session.commit()
            return None
        session.last_activity_at = utcnow()
        session.expires_at = token_expiry(app.config["SESSION_IDLE_MINUTES"])
        db.session.commit()
        return session

    def get_optional_user():
        active_session = get_session_from_cookie()
        if not active_session:
            return None
        return User.query.get(active_session.user_id)

    def require_auth(role=None):
        def decorator(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                active_session = get_session_from_cookie()
                if not active_session:
                    return jsonify({"error": "Authentication required"}), 401
                user = User.query.get(active_session.user_id)
                if not user:
                    return jsonify({"error": "User not found"}), 401
                if not user.is_active:
                    return jsonify({"error": "Account deactivated"}), 403
                if role and user.role != role:
                    return jsonify({"error": "Forbidden"}), 403
                request.current_user = user
                request.current_session = active_session
                return fn(*args, **kwargs)

            return wrapped

        return decorator

    def as_data():
        return request.get_json(silent=True) or request.form

    def create_slug(name):
        base = "-".join(name.lower().split())
        slug = "".join(ch for ch in base if ch.isalnum() or ch == "-").strip("-")
        if not slug:
            slug = f"category-{secrets.token_hex(3)}"
        existing = Category.query.filter_by(slug=slug).first()
        if existing:
            slug = f"{slug}-{secrets.token_hex(2)}"
        return slug

    def create_ebook_slug(title):
        base = "-".join((title or "ebook").lower().split())
        slug = "".join(ch for ch in base if ch.isalnum() or ch == "-").strip("-")
        if not slug:
            slug = f"ebook-{secrets.token_hex(3)}"
        candidate = slug
        while Ebook.query.filter_by(slug=candidate).first():
            candidate = f"{slug}-{secrets.token_hex(2)}"
        return candidate

    category_cache = {"expires_at": utcnow(), "data": {}}

    def clear_category_cache():
        category_cache["data"] = {}
        category_cache["expires_at"] = utcnow()

    def keyword_tokens(raw):
        if not raw:
            return []
        return [k.strip() for k in str(raw).split(",") if k.strip()]

    def log_search_query(term, result_count):
        user = get_optional_user()
        db.session.add(
            SearchQueryLog(
                term=term,
                user_id=user.id if user else None,
                ip_address=get_client_ip(),
                result_count=int(result_count),
                is_zero_result=int(result_count) == 0,
            )
        )
        db.session.commit()

    def ebook_to_dict(ebook, include_files=False, include_stats=False):
        category = Category.query.get(ebook.category_id) if ebook.category_id else None
        avg_rating, review_count = db.session.query(
            func.avg(Review.rating),
            func.count(Review.id),
        ).filter(Review.ebook_id == ebook.id).first()
        payload = {
            "id": ebook.id,
            "title": ebook.title,
            "description": ebook.description,
            "summary_text": ebook.summary_text,
            "author": ebook.author,
            "category": {"id": category.id, "name": category.name, "slug": category.slug} if category else None,
            "cover_image_path": ebook.cover_image_path,
            "slug": ebook.slug,
            "keywords": keyword_tokens(ebook.keywords),
            "preview_available": bool(ebook.preview_file_path),
            "is_featured": ebook.is_featured,
            "is_active": ebook.is_active,
            "average_rating": round(float(avg_rating), 2) if avg_rating is not None else None,
            "review_count": int(review_count or 0),
            "created_at": ebook.created_at.isoformat(),
            "updated_at": ebook.updated_at.isoformat(),
        }
        if include_files:
            payload["files"] = [
                {
                    "id": f.id,
                    "file_name": f.file_name,
                    "file_size": f.file_size,
                    "version_label": f.version_label,
                    "created_at": f.created_at.isoformat(),
                }
                for f in EbookFile.query.filter_by(ebook_id=ebook.id).order_by(EbookFile.created_at.desc()).all()
            ]
        if include_stats:
            payload["download_count"] = (
                db.session.query(func.count(DownloadEvent.id)).filter(DownloadEvent.ebook_id == ebook.id).scalar() or 0
            )
        return payload

    def write_upload(file_obj, folder):
        if not file_obj:
            return None, None, None
        safe_name = secure_filename(file_obj.filename)
        if not safe_name:
            return None, None, None
        unique_name = f"{secrets.token_hex(10)}-{safe_name}"
        full_path = folder / unique_name
        file_obj.save(full_path)
        return safe_name, str(full_path), full_path.stat().st_size

    def create_access_code(length=16):
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        while True:
            value = "".join(secrets.choice(alphabet) for _ in range(length))
            if not AccessCode.query.filter_by(code_value=value).first():
                return value

    def code_attempt_session_key():
        return request.cookies.get("session_token")

    def code_attempts_exceeded():
        window_start = utcnow() - timedelta(minutes=app.config["CODE_ATTEMPT_WINDOW_MINUTES"])
        attempts = CodeAttempt.query.filter(
            CodeAttempt.successful.is_(False),
            CodeAttempt.attempted_at >= window_start,
            (CodeAttempt.ip_address == get_client_ip()) | (CodeAttempt.session_key == code_attempt_session_key()),
        ).count()
        return attempts >= app.config["CODE_ATTEMPT_MAX"]

    def code_captcha_required():
        window_start = utcnow() - timedelta(minutes=app.config["CODE_ATTEMPT_WINDOW_MINUTES"])
        failed_recent = CodeAttempt.query.filter(
            CodeAttempt.successful.is_(False),
            CodeAttempt.attempted_at >= window_start,
            (CodeAttempt.ip_address == get_client_ip()) | (CodeAttempt.session_key == code_attempt_session_key()),
        ).count()
        return failed_recent >= app.config["CODE_CAPTCHA_THRESHOLD"]

    def record_code_attempt(success):
        db.session.add(
            CodeAttempt(
                session_key=code_attempt_session_key(),
                ip_address=get_client_ip(),
                successful=success,
            )
        )
        db.session.commit()


    def create_download_session(code, user):
        session = DownloadSession(
            code_id=code.id,
            ebook_id=code.ebook_id,
            user_id=user.id if user else None,
            ip_address=get_client_ip(),
            device_info=request.user_agent.string,
            access_token=secrets.token_urlsafe(32),
            expires_at=utcnow() + timedelta(minutes=app.config["DOWNLOAD_SESSION_TTL_MINUTES"]),
            is_active=True,
        )
        db.session.add(session)
        db.session.commit()
        return session

    def build_code_download_token(download_session_id, file_id=None, bundle=False):
        jti = secrets.token_urlsafe(12)
        token = code_serializer.dumps(
            {
                "download_session_id": download_session_id,
                "file_id": file_id,
                "bundle": bundle,
                "jti": jti,
            }
        )
        return token

    def get_valid_download_session(session_id):
        session = DownloadSession.query.get(session_id)
        if not session or not session.is_active:
            return None, "download_session_invalid"
        if session.expires_at < utcnow():
            session.is_active = False
            db.session.commit()
            return None, "download_session_expired"
        if session.ip_address != get_client_ip():
            return None, "ip_mismatch"
        return session, None

    def log_download_attempt(session_id, file_id=None, success=False, completed=False, reason=None):
        db.session.add(
            DownloadAttemptLog(
                download_session_id=session_id,
                file_id=file_id,
                ip_address=get_client_ip(),
                was_successful=success,
                download_completed=completed,
                error_reason=reason,
            )
        )
        db.session.commit()

    def review_submission_rate_limited(user_id):
        window_start = utcnow() - timedelta(minutes=app.config["REVIEW_RATE_LIMIT_WINDOW_MINUTES"])
        attempts = ReviewAttemptLog.query.filter(
            ReviewAttemptLog.attempted_at >= window_start,
            ReviewAttemptLog.was_successful.is_(False),
            (ReviewAttemptLog.user_id == user_id) | (ReviewAttemptLog.ip_address == get_client_ip()),
        ).count()
        return attempts >= app.config["REVIEW_RATE_LIMIT_MAX_ATTEMPTS"]

    def log_review_attempt(user_id, ebook_id, success, reason=None):
        db.session.add(
            ReviewAttemptLog(
                user_id=user_id,
                ebook_id=ebook_id,
                ip_address=get_client_ip(),
                was_successful=success,
                reason=reason,
            )
        )
        db.session.commit()

    def record_download_history(user_id, ebook_id, version_label, code_id=None):
        db.session.add(
            DownloadHistory(
                user_id=user_id,
                ebook_id=ebook_id,
                code_id=code_id,
                version_label=version_label,
            )
        )

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/admin")
    @require_auth(role="admin")
    def admin_page():
        return render_template("admin.html")

    @app.get("/profile")
    @require_auth()
    def profile_page():
        return render_template("profile.html")

    @app.get("/auth/captcha")
    def captcha():
        challenge, answer = generate_captcha_pair()
        return jsonify({"challenge": challenge, "answer_token": answer})

    @app.post("/auth/register")
    def register():
        data = as_data()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 409
        user = User(email=email, password_hash=generate_password_hash(password), role="user")
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User registered"}), 201

    @app.post("/auth/login")
    def login():
        data = as_data()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        captcha_answer = (data.get("captcha_answer") or "").strip()
        captcha_token = (data.get("captcha_token") or "").strip()

        if not all([email, password, captcha_answer, captcha_token]):
            return jsonify({"error": "Missing credentials or captcha"}), 400
        if captcha_answer != captcha_token:
            return jsonify({"error": "Invalid captcha"}), 400
        if login_blocked(email):
            log_security_event("login_rate_limited", details=f"email={email}")
            return jsonify({"error": "Too many login attempts. Try later."}), 429

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            record_login_attempt(email, False)
            return jsonify({"error": "Invalid credentials"}), 401
        if not user.is_active:
            record_login_attempt(email, False)
            return jsonify({"error": "Account deactivated"}), 403

        token = issue_session(user)
        record_login_attempt(email, True)
        resp = make_response(jsonify({"message": "Logged in", "role": user.role}))
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite="Strict",
            max_age=app.config["SESSION_IDLE_MINUTES"] * 60,
        )
        return resp

    @app.post("/auth/logout")
    @require_auth()
    def logout():
        db.session.delete(request.current_session)
        db.session.commit()
        resp = make_response(jsonify({"message": "Logged out"}))
        resp.delete_cookie("session_token")
        return resp

    @app.post("/auth/password-reset/request")
    def request_password_reset():
        data = as_data()
        email = (data.get("email") or "").strip().lower()
        if password_reset_rate_limited(email):
            log_security_event("password_reset_rate_limited", details=f"email={email}")
            return jsonify({"error": "Too many password reset attempts. Try again later."}), 429

        record_password_reset_attempt(email)
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"message": "If the account exists, a reset email will be sent."})

        token = secrets.token_urlsafe(48)
        reset = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=token_expiry(app.config["PASSWORD_RESET_TTL_MINUTES"]),
        )
        db.session.add(reset)
        db.session.commit()

        return jsonify(
            {
                "message": "Password reset token generated and sent via email provider.",
                "dev_token_preview": token,
            }
        )

    @app.post("/auth/password-reset/confirm")
    def confirm_password_reset():
        data = as_data()
        token = (data.get("token") or "").strip()
        new_password = data.get("new_password") or ""
        entry = PasswordResetToken.query.filter_by(token=token).first()
        if not entry or entry.expires_at < utcnow():
            return jsonify({"error": "Invalid or expired token"}), 400

        user = User.query.get(entry.user_id)
        user.password_hash = generate_password_hash(new_password)
        db.session.delete(entry)
        Session.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({"message": "Password updated"})

    @app.post("/auth/change-email")
    @require_auth()
    def change_email():
        data = as_data()
        new_email = (data.get("new_email") or "").strip().lower()
        password = data.get("password") or ""
        if not check_password_hash(request.current_user.password_hash, password):
            return jsonify({"error": "Invalid password"}), 403
        if User.query.filter_by(email=new_email).first():
            return jsonify({"error": "Email already in use"}), 409
        request.current_user.email = new_email
        db.session.commit()
        return jsonify({"message": "Email updated"})

    @app.post("/auth/change-password")
    @require_auth()
    def change_password():
        data = as_data()
        old_password = data.get("old_password") or ""
        new_password = data.get("new_password") or ""
        if not check_password_hash(request.current_user.password_hash, old_password):
            return jsonify({"error": "Invalid current password"}), 403
        request.current_user.password_hash = generate_password_hash(new_password)
        Session.query.filter(Session.user_id == request.current_user.id, Session.id != request.current_session.id).delete()
        db.session.commit()
        return jsonify({"message": "Password updated; other sessions revoked"})

    @app.get("/auth/me")
    @require_auth()
    def me():
        user = request.current_user
        return jsonify({"id": user.id, "email": user.email, "role": user.role})

    @app.get("/notifications/active")
    def active_notifications():
        system_rows = SiteNotification.query.filter_by(is_active=True).order_by(SiteNotification.created_at.desc()).limit(5).all()
        featured = Ebook.query.filter_by(is_active=True, is_featured=True).order_by(Ebook.created_at.desc()).limit(5).all()

        maintenance_enabled = get_setting("maintenance_mode", "false").lower() == "true"
        maintenance_message = get_setting("maintenance_message", "Maintenance in progress")

        return jsonify(
            {
                "maintenance": {"enabled": maintenance_enabled, "message": maintenance_message},
                "system": [
                    {
                        "id": row.id,
                        "message": row.message,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in system_rows
                ],
                "promotions": [
                    {
                        "id": ebook.id,
                        "title": ebook.title,
                        "author": ebook.author,
                        "slug": ebook.slug,
                    }
                    for ebook in featured
                ],
            }
        )

    @app.post("/admin/create")
    def create_admin():
        data = as_data()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if len(password) < 12 or password.lower() == password or password.upper() == password or not any(
            ch.isdigit() for ch in password
        ):
            return jsonify({"error": "Admin password does not meet strength requirements"}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 409
        admin = User(email=email, password_hash=generate_password_hash(password), role="admin")
        db.session.add(admin)
        db.session.commit()
        return jsonify({"message": "Admin created"}), 201

    @app.post("/admin/login")
    def admin_login():
        data = as_data()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if login_blocked(email):
            log_security_event("login_rate_limited", details=f"email={email}")
            return jsonify({"error": "Too many login attempts. Try later."}), 429

        user = User.query.filter_by(email=email, role="admin").first()
        if not user or not check_password_hash(user.password_hash, password):
            record_login_attempt(email, False)
            return jsonify({"error": "Invalid admin credentials"}), 401
        if not user.is_active:
            record_login_attempt(email, False)
            return jsonify({"error": "Account deactivated"}), 403

        token = issue_session(user)
        record_login_attempt(email, True)
        db.session.add(
            AuditLog(
                admin_user_id=user.id,
                action="admin_login",
                ip_address=get_client_ip(),
                device_info=request.user_agent.string,
            )
        )
        db.session.commit()

        resp = make_response(jsonify({"message": "Admin logged in"}))
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite="Strict",
            max_age=app.config["SESSION_IDLE_MINUTES"] * 60,
        )
        return resp

    @app.get("/admin/audit-logs")
    @require_auth(role="admin")
    def admin_audit_logs():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
        return jsonify(
            [
                {
                    "admin_user_id": log.admin_user_id,
                    "action": log.action,
                    "ip_address": log.ip_address,
                    "device_info": log.device_info,
                    "created_at": log.created_at.isoformat(),
                }
                for log in logs
            ]
        )

    @app.post("/admin/categories")
    @require_auth(role="admin")
    def create_category():
        data = as_data()
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Category name is required"}), 400
        category = Category(name=name, slug=create_slug(name))
        db.session.add(category)
        db.session.commit()
        return jsonify({"id": category.id, "name": category.name, "slug": category.slug}), 201

    @app.get("/categories")
    def list_categories():
        categories = Category.query.order_by(Category.name.asc()).all()
        return jsonify(
            [
                {
                    "id": c.id,
                    "name": c.name,
                    "slug": c.slug,
                    "created_at": c.created_at.isoformat(),
                }
                for c in categories
            ]
        )

    @app.post("/admin/ebooks")
    @require_auth(role="admin")
    def create_ebook():
        data = as_data()
        title = (data.get("title") or "").strip()
        author = (data.get("author") or "").strip()
        if not title or not author:
            return jsonify({"error": "title and author are required"}), 400

        category_id = data.get("category_id")
        category = Category.query.get(category_id) if category_id else None
        if category_id and not category:
            return jsonify({"error": "Invalid category_id"}), 400

        ebook = Ebook(
            title=title,
            description=data.get("description"),
            summary_text=data.get("summary_text"),
            author=author,
            category_id=category.id if category else None,
            cover_image_path=(data.get("cover_image_path") or "").strip() or None,
            slug=create_ebook_slug((data.get("slug") or title)),
            keywords=(data.get("keywords") or "").strip() or None,
            is_featured=str(data.get("is_featured", "false")).lower() == "true",
            is_active=True,
        )
        db.session.add(ebook)
        db.session.commit()
        clear_category_cache()
        log_admin_action(request.current_user.id, f"ebook_create:{ebook.id}")
        return jsonify(ebook_to_dict(ebook, include_files=True)), 201

    @app.post("/admin/ebooks/<int:ebook_id>/upload-file")
    @require_auth(role="admin")
    def upload_ebook_file(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        uploaded = request.files.get("file")
        if not uploaded:
            return jsonify({"error": "file is required"}), 400
        original_name, stored_path, size = write_upload(uploaded, files_root)
        version_label = (request.form.get("version_label") or "v1.0").strip()
        record = EbookFile(
            ebook_id=ebook.id,
            file_name=original_name,
            file_path=stored_path,
            file_size=size,
            version_label=version_label,
        )
        db.session.add(record)
        db.session.commit()
        return jsonify({"message": "file uploaded", "file_id": record.id}), 201

    @app.post("/admin/ebooks/<int:ebook_id>/upload-preview")
    @require_auth(role="admin")
    def upload_preview_file(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        uploaded = request.files.get("file")
        if not uploaded:
            return jsonify({"error": "file is required"}), 400
        _, stored_path, _ = write_upload(uploaded, previews_root)
        ebook.preview_file_path = stored_path
        db.session.commit()
        return jsonify({"message": "preview uploaded"}), 201

    @app.patch("/admin/ebooks/<int:ebook_id>")
    @require_auth(role="admin")
    def update_ebook(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        data = as_data()

        if "title" in data:
            ebook.title = (data.get("title") or ebook.title).strip()
        if "description" in data:
            ebook.description = data.get("description")
        if "summary_text" in data:
            ebook.summary_text = data.get("summary_text")
        if "author" in data:
            ebook.author = (data.get("author") or ebook.author).strip()
        if "cover_image_path" in data:
            ebook.cover_image_path = (data.get("cover_image_path") or "").strip() or None
        if "slug" in data:
            requested = (data.get("slug") or "").strip()
            if requested and requested != ebook.slug and Ebook.query.filter_by(slug=requested).first():
                return jsonify({"error": "Slug already exists"}), 409
            ebook.slug = requested or ebook.slug or create_ebook_slug(ebook.title)
        if "keywords" in data:
            ebook.keywords = (data.get("keywords") or "").strip() or None
        if "is_featured" in data:
            ebook.is_featured = str(data.get("is_featured", "false")).lower() == "true"
        if "is_active" in data:
            ebook.is_active = str(data.get("is_active", "true")).lower() == "true"
        if "category_id" in data:
            category_id = data.get("category_id")
            if not category_id:
                ebook.category_id = None
            else:
                category = Category.query.get(category_id)
                if not category:
                    return jsonify({"error": "Invalid category_id"}), 400
                ebook.category_id = category.id

        db.session.commit()
        clear_category_cache()
        log_admin_action(request.current_user.id, f"ebook_update:{ebook.id}")
        return jsonify(ebook_to_dict(ebook, include_files=True, include_stats=True))

    @app.delete("/admin/ebooks/<int:ebook_id>")
    @require_auth(role="admin")
    def delete_or_deactivate_ebook(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        mode = (request.args.get("mode") or "deactivate").lower()
        if mode == "delete":
            files = EbookFile.query.filter_by(ebook_id=ebook.id).all()
            for item in files:
                try:
                    Path(item.file_path).unlink(missing_ok=True)
                except OSError:
                    pass
                db.session.delete(item)
            if ebook.preview_file_path:
                try:
                    Path(ebook.preview_file_path).unlink(missing_ok=True)
                except OSError:
                    pass
            Favorite.query.filter_by(ebook_id=ebook.id).delete()
            db.session.delete(ebook)
            db.session.commit()
            clear_category_cache()
            log_admin_action(request.current_user.id, f"ebook_delete:{ebook.id}")
            return jsonify({"message": "ebook deleted"})

        ebook.is_active = False
        db.session.commit()
        clear_category_cache()
        log_admin_action(request.current_user.id, f"ebook_deactivate:{ebook.id}")
        return jsonify({"message": "ebook deactivated"})

    @app.get("/search/suggestions")
    def search_suggestions():
        q = (request.args.get("q") or "").strip().lower()
        if not q:
            return jsonify([])
        suggestions = []
        titles = Ebook.query.filter(func.lower(Ebook.title).contains(q), Ebook.is_active.is_(True)).limit(5).all()
        authors = Ebook.query.filter(func.lower(Ebook.author).contains(q), Ebook.is_active.is_(True)).limit(5).all()
        cats = Category.query.filter(func.lower(Category.name).contains(q)).limit(5).all()
        suggestions.extend([{"type": "title", "value": e.title} for e in titles])
        suggestions.extend([{"type": "author", "value": e.author} for e in authors])
        suggestions.extend([{"type": "category", "value": c.name, "slug": c.slug} for c in cats])
        seen = set()
        unique = []
        for item in suggestions:
            key = (item["type"], item["value"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return jsonify(unique[:10])

    @app.get("/ebooks")
    def list_ebooks():
        category_slug = (request.args.get("category") or "").strip()
        author = (request.args.get("author") or "").strip().lower()
        q = (request.args.get("q") or "").strip().lower()
        featured = (request.args.get("featured") or "").strip().lower() == "true"
        min_rating = request.args.get("min_rating", type=float)
        recent_days = request.args.get("recent_days", type=int)
        sort_by = (request.args.get("sort") or "newest").strip().lower()
        page = max(request.args.get("page", 1, type=int), 1)
        per_page = min(max(request.args.get("per_page", 20, type=int), 1), 100)

        query = Ebook.query.filter_by(is_active=True)
        if category_slug:
            category = Category.query.filter_by(slug=category_slug).first()
            if not category:
                log_search_query(q or f"category:{category_slug}", 0)
                return jsonify({"items": [], "pagination": {"page": page, "per_page": per_page, "total": 0}})
            query = query.filter_by(category_id=category.id)
        if featured:
            query = query.filter_by(is_featured=True)
        if author:
            query = query.filter(func.lower(Ebook.author).contains(author))
        if q:
            query = query.filter(
                (func.lower(Ebook.title).contains(q))
                | (func.lower(Ebook.author).contains(q))
                | (func.lower(Ebook.description).contains(q))
                | (func.lower(Ebook.keywords).contains(q))
            )

        ebooks = query.all()

        scored = []
        for e in ebooks:
            score = 0
            if q:
                title = (e.title or "").lower()
                author_v = (e.author or "").lower()
                desc = (e.description or "").lower()
                if q in title:
                    score += 100
                if q in author_v:
                    score += 50
                if q in desc:
                    score += 20
            avg, cnt = db.session.query(func.avg(Review.rating), func.count(Review.id)).filter(Review.ebook_id == e.id).first()
            avg = float(avg) if avg is not None else 0.0
            cnt = int(cnt or 0)
            dls = int(db.session.query(func.count(DownloadHistory.id)).filter(DownloadHistory.ebook_id == e.id).scalar() or 0)
            scored.append((e, score, avg, cnt, dls))

        if min_rating is not None:
            scored = [row for row in scored if row[2] >= float(min_rating)]
        if recent_days:
            cutoff = utcnow() - timedelta(days=recent_days)
            scored = [row for row in scored if row[0].created_at >= cutoff]

        if sort_by == "highest_rated":
            scored.sort(key=lambda r: (r[2], r[3], r[0].title or ""), reverse=True)
        elif sort_by == "most_downloaded":
            scored.sort(key=lambda r: (r[4], r[2], r[0].title or ""), reverse=True)
        elif sort_by == "alphabetical":
            scored.sort(key=lambda r: (r[0].title or "").lower())
        elif q:
            scored.sort(key=lambda r: (r[1], r[2], r[4]), reverse=True)
        else:
            scored.sort(key=lambda r: r[0].created_at, reverse=True)

        total = len(scored)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        page_items = [ebook_to_dict(r[0], include_files=True) for r in scored[start_idx:end_idx]]

        log_search_query(q or "browse", total)
        return jsonify(
            {
                "items": page_items,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "pages": (total + per_page - 1) // per_page,
                },
            }
        )

    @app.get("/categories/<slug>/ebooks")
    def category_ebooks(slug):
        now = utcnow()
        cache_entry = category_cache["data"].get(slug)
        if cache_entry and cache_entry["expires_at"] > now:
            return jsonify({"cached": True, "items": cache_entry["items"]})

        category = Category.query.filter_by(slug=slug).first_or_404()
        ebooks = Ebook.query.filter_by(category_id=category.id, is_active=True).order_by(Ebook.created_at.desc()).all()
        payload = [ebook_to_dict(e, include_files=False) for e in ebooks]
        category_cache["data"][slug] = {"expires_at": now + timedelta(minutes=5), "items": payload}
        return jsonify({"cached": False, "items": payload})

    @app.get("/ebooks/<int:ebook_id>")
    def ebook_detail(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        return jsonify(ebook_to_dict(ebook, include_files=True))


    @app.get("/ebook/<slug>/page")
    def ebook_detail_page(slug):
        return render_template("ebook.html", ebook_slug=slug)

    @app.get("/ebook/<slug>")
    def ebook_detail_by_slug(slug):
        ebook = Ebook.query.filter_by(slug=slug, is_active=True).first_or_404()
        category = Category.query.get(ebook.category_id) if ebook.category_id else None
        avg_rating, review_count = db.session.query(func.avg(Review.rating), func.count(Review.id)).filter(Review.ebook_id == ebook.id).first()
        seo = {
            "meta_title": f"{ebook.title} by {ebook.author} | Ebook Store",
            "meta_description": (ebook.description or ebook.summary_text or "Digital ebook available on Ebook Store.")[:160],
            "canonical_url": f"/ebook/{ebook.slug}",
            "structured_data": {
                "@context": "https://schema.org",
                "@type": "Book",
                "name": ebook.title,
                "author": {"@type": "Person", "name": ebook.author},
                "description": ebook.description or ebook.summary_text,
                "genre": category.name if category else None,
                "aggregateRating": {
                    "@type": "AggregateRating",
                    "ratingValue": round(float(avg_rating), 2) if avg_rating is not None else None,
                    "reviewCount": int(review_count or 0),
                },
            },
        }
        response = ebook_to_dict(ebook, include_files=True)
        response["seo"] = seo
        return jsonify(response)

    @app.get("/ebooks/<int:ebook_id>/share")
    def ebook_share_links(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        slug_part = ebook.slug or str(ebook.id)
        base = f"/ebook/{slug_part}"
        return jsonify(
            {
                "ebook_page": base,
                "preview_page": f"/ebooks/{ebook.id}/preview",
                "reviews_page": f"/ebooks/{ebook.id}/reviews",
                "social_share": {
                    "x": f"https://twitter.com/intent/tweet?text={ebook.title}&url={base}",
                    "facebook": f"https://www.facebook.com/sharer/sharer.php?u={base}",
                    "linkedin": f"https://www.linkedin.com/sharing/share-offsite/?url={base}",
                },
            }
        )

    @app.get("/ebooks/<int:ebook_id>/preview")
    def ebook_preview(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        files_preview = [
            {"file_name": f.file_name, "file_size": f.file_size, "version_label": f.version_label}
            for f in EbookFile.query.filter_by(ebook_id=ebook.id).all()
        ]
        payload = {
            "ebook_id": ebook.id,
            "title": ebook.title,
            "summary_text": ebook.summary_text,
            "sample_preview_available": bool(ebook.preview_file_path),
            "bundle_file_list_preview": files_preview,
        }
        return jsonify(payload)

    @app.get("/ebooks/<int:ebook_id>/reviews")
    def list_reviews(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        rows = Review.query.filter_by(ebook_id=ebook.id).order_by(Review.created_at.desc()).all()
        return jsonify(
            [
                {
                    "id": row.id,
                    "ebook_id": row.ebook_id,
                    "user_id": row.user_id,
                    "rating": row.rating,
                    "review_text": row.review_text,
                    "created_at": row.created_at.isoformat(),
                    "updated_at": row.updated_at.isoformat(),
                }
                for row in rows
            ]
        )

    @app.post("/ebooks/<int:ebook_id>/reviews")
    @require_auth()
    def create_review(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        if review_submission_rate_limited(request.current_user.id):
            log_review_attempt(request.current_user.id, ebook_id, False, "rate_limited")
            log_security_event("review_rate_limited", user_id=request.current_user.id, details=f"ebook_id={ebook_id}")
            return jsonify({"error": "Too many review attempts. Try again later."}), 429

        data = as_data()
        try:
            rating = int(data.get("rating"))
        except (TypeError, ValueError):
            log_review_attempt(request.current_user.id, ebook_id, False, "invalid_rating")
            return jsonify({"error": "Rating must be an integer from 1 to 5."}), 400
        if rating < 1 or rating > 5:
            log_review_attempt(request.current_user.id, ebook_id, False, "rating_out_of_range")
            return jsonify({"error": "Rating must be between 1 and 5."}), 400

        existing = Review.query.filter_by(ebook_id=ebook_id, user_id=request.current_user.id).first()
        if existing:
            log_review_attempt(request.current_user.id, ebook_id, False, "duplicate_review")
            return jsonify({"error": "You have already reviewed this ebook."}), 409

        review = Review(
            ebook_id=ebook_id,
            user_id=request.current_user.id,
            rating=rating,
            review_text=(data.get("review_text") or "").strip() or None,
        )
        db.session.add(review)
        db.session.commit()
        log_review_attempt(request.current_user.id, ebook_id, True)
        return jsonify({"message": "Review posted", "review_id": review.id}), 201

    @app.patch("/ebooks/<int:ebook_id>/reviews/<int:review_id>")
    @require_auth()
    def edit_review(ebook_id, review_id):
        review = Review.query.filter_by(id=review_id, ebook_id=ebook_id, user_id=request.current_user.id).first()
        if not review:
            return jsonify({"error": "Review not found"}), 404

        data = as_data()
        if "rating" in data:
            try:
                rating = int(data.get("rating"))
            except (TypeError, ValueError):
                return jsonify({"error": "Rating must be an integer from 1 to 5."}), 400
            if rating < 1 or rating > 5:
                return jsonify({"error": "Rating must be between 1 and 5."}), 400
            review.rating = rating
        if "review_text" in data:
            review.review_text = (data.get("review_text") or "").strip() or None

        db.session.commit()
        return jsonify({"message": "Review updated"})

    @app.delete("/admin/reviews/<int:review_id>")
    @require_auth(role="admin")
    def admin_delete_review(review_id):
        review = Review.query.get_or_404(review_id)
        db.session.delete(review)
        db.session.commit()
        return jsonify({"message": "Review deleted"})

    @app.get("/profile/reviews")
    @require_auth()
    def profile_reviews():
        rows = Review.query.filter_by(user_id=request.current_user.id).order_by(Review.created_at.desc()).all()
        payload = []
        for row in rows:
            ebook = Ebook.query.get(row.ebook_id)
            payload.append(
                {
                    "review_id": row.id,
                    "ebook_id": row.ebook_id,
                    "ebook_title": ebook.title if ebook else None,
                    "ebook_slug": ebook.slug if ebook else None,
                    "rating": row.rating,
                    "review_text": row.review_text,
                    "created_at": row.created_at.isoformat(),
                    "updated_at": row.updated_at.isoformat(),
                    "can_edit": True,
                }
            )
        return jsonify(payload)

    @app.get("/admin/reviews/analytics")
    @require_auth(role="admin")
    def review_analytics():
        most_reviewed_rows = (
            db.session.query(Review.ebook_id, func.count(Review.id).label("review_count"))
            .group_by(Review.ebook_id)
            .order_by(func.count(Review.id).desc())
            .limit(10)
            .all()
        )
        highest_rated_rows = (
            db.session.query(Review.ebook_id, func.avg(Review.rating).label("avg_rating"), func.count(Review.id).label("cnt"))
            .group_by(Review.ebook_id)
            .having(func.count(Review.id) >= 1)
            .order_by(func.avg(Review.rating).desc(), func.count(Review.id).desc())
            .limit(10)
            .all()
        )
        recent = Review.query.order_by(Review.created_at.desc()).limit(20).all()

        def ebook_title(eid):
            e = Ebook.query.get(eid)
            return e.title if e else None

        return jsonify(
            {
                "most_reviewed_ebooks": [
                    {"ebook_id": eid, "ebook_title": ebook_title(eid), "review_count": int(cnt)}
                    for eid, cnt in most_reviewed_rows
                ],
                "highest_rated_ebooks": [
                    {
                        "ebook_id": eid,
                        "ebook_title": ebook_title(eid),
                        "average_rating": round(float(avg), 2) if avg is not None else None,
                        "review_count": int(cnt),
                    }
                    for eid, avg, cnt in highest_rated_rows
                ],
                "recent_review_activity": [
                    {
                        "review_id": r.id,
                        "ebook_id": r.ebook_id,
                        "ebook_title": ebook_title(r.ebook_id),
                        "user_id": r.user_id,
                        "rating": r.rating,
                        "created_at": r.created_at.isoformat(),
                    }
                    for r in recent
                ],
            }
        )

    @app.post("/favorites/<int:ebook_id>")
    @require_auth()
    def add_favorite(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        exists = Favorite.query.filter_by(user_id=request.current_user.id, ebook_id=ebook.id).first()
        if exists:
            return jsonify({"message": "already in favorites"})
        db.session.add(Favorite(user_id=request.current_user.id, ebook_id=ebook.id))
        db.session.commit()
        return jsonify({"message": "added to favorites"}), 201

    @app.delete("/favorites/<int:ebook_id>")
    @require_auth()
    def remove_favorite(ebook_id):
        favorite = Favorite.query.filter_by(user_id=request.current_user.id, ebook_id=ebook_id).first()
        if not favorite:
            return jsonify({"message": "not in favorites"})
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({"message": "removed from favorites"})

    @app.get("/favorites")
    @require_auth()
    def list_favorites():
        sort_by = (request.args.get("sort") or "recent").strip().lower()
        favorites = Favorite.query.filter_by(user_id=request.current_user.id).order_by(Favorite.created_at.desc()).all()

        rows = []
        for fav in favorites:
            ebook = Ebook.query.get(fav.ebook_id)
            if not ebook or not ebook.is_active:
                continue
            payload = ebook_to_dict(ebook, include_files=False)
            payload["favorited_at"] = fav.created_at.isoformat()
            rows.append(payload)

        if sort_by == "title":
            rows.sort(key=lambda r: (r.get("title") or "").lower())
        elif sort_by == "rating":
            rows.sort(key=lambda r: (r.get("average_rating") is None, -(r.get("average_rating") or 0), (r.get("title") or "").lower()))
        else:
            rows.sort(key=lambda r: r.get("favorited_at"), reverse=True)

        return jsonify(rows)

    @app.get("/ebooks/<int:ebook_id>/download-link/<int:file_id>")
    @require_auth()
    def generate_download_link(ebook_id, file_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        file_item = EbookFile.query.filter_by(id=file_id, ebook_id=ebook.id).first_or_404()
        token = serializer.dumps({"uid": request.current_user.id, "ebook_id": ebook.id, "file_id": file_item.id})
        return jsonify({
            "download_url": f"/download/{token}",
            "expires_in_seconds": app.config["DOWNLOAD_TOKEN_TTL_SECONDS"],
        })

    @app.get("/download/<token>")
    @require_auth()
    def download_file(token):
        try:
            payload = serializer.loads(token, max_age=app.config["DOWNLOAD_TOKEN_TTL_SECONDS"])
        except BadSignature:
            return jsonify({"error": "Invalid or expired token"}), 400

        if payload.get("uid") != request.current_user.id:
            return jsonify({"error": "Forbidden"}), 403

        file_item = EbookFile.query.filter_by(id=payload.get("file_id"), ebook_id=payload.get("ebook_id")).first_or_404()
        file_path = Path(file_item.file_path)
        if not file_path.exists():
            return jsonify({"error": "File unavailable"}), 404

        db.session.add(
            DownloadEvent(
                user_id=request.current_user.id,
                ebook_id=payload.get("ebook_id"),
                ebook_file_id=file_item.id,
            )
        )
        record_download_history(
            user_id=request.current_user.id,
            ebook_id=payload.get("ebook_id"),
            version_label=file_item.version_label,
            code_id=None,
        )
        db.session.commit()
        return send_file(file_path, as_attachment=True, download_name=file_item.file_name)

    @app.get("/codes/captcha")
    def code_captcha():
        challenge, answer = generate_captcha_pair()
        return jsonify({"challenge": challenge, "answer_token": answer})

    @app.post("/codes/validate")
    def validate_code():
        if code_attempts_exceeded():
            log_security_event("code_rate_limited", details="validate_code")
            return jsonify({"error": "Too many code attempts. Please try again later.", "retry_available": True}), 429

        data = as_data()
        code_value = (data.get("code_value") or "").strip().upper()
        captcha_answer = (data.get("captcha_answer") or "").strip()
        captcha_token = (data.get("captcha_token") or "").strip()

        if not code_value:
            record_code_attempt(False)
            return jsonify({"error": "Code is required.", "retry_available": True}), 400

        if code_captcha_required() and (not captcha_answer or captcha_answer != captcha_token):
            record_code_attempt(False)
            return jsonify({"error": "Captcha required after repeated failures.", "retry_available": True}), 400

        user = get_optional_user()
        code = AccessCode.query.filter_by(code_value=code_value).first()
        if not code:
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=None,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="code_not_found",
                )
            )
            db.session.commit()
            return jsonify({"error": "Code not found.", "retry_available": True}), 404

        if not code.is_active:
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=code.id,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="code_deactivated",
                )
            )
            db.session.commit()
            return jsonify({"error": "Code has been deactivated.", "retry_available": True}), 400

        if code.expires_at < utcnow():
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=code.id,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="code_expired",
                )
            )
            db.session.commit()
            return jsonify({"error": "Code has expired.", "retry_available": True}), 400

        if code.is_used:
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=code.id,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="code_already_used",
                )
            )
            db.session.commit()
            return jsonify({"error": "Code was already used.", "retry_available": True}), 400

        ebook = Ebook.query.get(code.ebook_id)
        if not ebook or not ebook.is_active:
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=code.id,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="ebook_unavailable",
                )
            )
            db.session.commit()
            return jsonify({"error": "Ebook unavailable for this code.", "retry_available": True}), 400

        files = EbookFile.query.filter_by(ebook_id=ebook.id).order_by(EbookFile.created_at.desc()).all()
        if not files:
            record_code_attempt(False)
            db.session.add(
                CodeUsageLog(
                    code_id=code.id,
                    user_id=user.id if user else None,
                    ip_address=get_client_ip(),
                    device_info=request.user_agent.string,
                    was_successful=False,
                    failure_reason="ebook_files_missing",
                )
            )
            db.session.commit()
            return jsonify({"error": "No downloadable files available for this ebook.", "retry_available": True}), 400

        code.is_used = True
        usage = CodeUsageLog(
            code_id=code.id,
            user_id=user.id if user else None,
            ip_address=get_client_ip(),
            device_info=request.user_agent.string,
            was_successful=True,
            download_completed=False,
        )
        db.session.add(usage)
        db.session.commit()
        record_code_attempt(True)

        download_session = create_download_session(code, user)
        file_links = [
            {
                "file_id": f.id,
                "file_name": f.file_name,
                "file_size": f.file_size,
                "download_url": f"/download/code/{build_code_download_token(download_session.id, file_id=f.id)}",
            }
            for f in files
        ]
        bundle_url = f"/download/code/bundle/{build_code_download_token(download_session.id, bundle=True)}"

        return jsonify(
            {
                "message": "Code accepted.",
                "confirmation": "Code accepted, choose a file to start download.",
                "download_session": {
                    "id": download_session.id,
                    "expires_at": download_session.expires_at.isoformat(),
                    "expires_in_seconds": app.config["DOWNLOAD_SESSION_TTL_MINUTES"] * 60,
                },
                "ebook_id": ebook.id,
                "usage_log_id": usage.id,
                "files": file_links,
                "bundle_download_url": bundle_url,
                "home_url": "/",
            }
        )

    @app.get("/download/code/<token>")
    def download_by_code(token):
        try:
            payload = code_serializer.loads(token, max_age=app.config["CODE_TOKEN_TTL_SECONDS"])
        except BadSignature:
            return jsonify({"error": "Invalid or expired code download token", "retry_available": True}), 400

        jti = payload.get("jti")
        if DownloadTokenUse.query.filter_by(token_jti=jti).first():
            return jsonify({"error": "This download link was already used.", "retry_available": True}), 400

        session, error = get_valid_download_session(payload.get("download_session_id"))
        if not session:
            return jsonify({"error": f"Download session invalid: {error}", "retry_available": True}), 400

        file_item = EbookFile.query.filter_by(id=payload.get("file_id"), ebook_id=session.ebook_id).first()
        if not file_item:
            log_download_attempt(session.id, file_id=payload.get("file_id"), reason="file_not_found")
            return jsonify({"error": "File not found for this session.", "retry_available": True}), 404

        file_path = Path(file_item.file_path)
        if not file_path.exists():
            log_download_attempt(session.id, file_id=file_item.id, reason="file_unavailable")
            return jsonify({"error": "File unavailable", "retry_available": True}), 404

        db.session.add(DownloadTokenUse(token_jti=jti, download_session_id=session.id, file_id=file_item.id))
        log_download_attempt(session.id, file_id=file_item.id, success=True, completed=True)
        if session.user_id:
            db.session.add(DownloadEvent(user_id=session.user_id, ebook_id=session.ebook_id, ebook_file_id=file_item.id))
            record_download_history(
                user_id=session.user_id,
                ebook_id=session.ebook_id,
                version_label=file_item.version_label,
                code_id=session.code_id,
            )
        db.session.commit()
        return send_file(file_path, as_attachment=True, download_name=file_item.file_name)

    @app.get("/download/code/bundle/<token>")
    def download_bundle_by_code(token):
        try:
            payload = code_serializer.loads(token, max_age=app.config["CODE_TOKEN_TTL_SECONDS"])
        except BadSignature:
            return jsonify({"error": "Invalid or expired bundle token", "retry_available": True}), 400

        if not payload.get("bundle"):
            return jsonify({"error": "Invalid bundle request", "retry_available": True}), 400

        jti = payload.get("jti")
        if DownloadTokenUse.query.filter_by(token_jti=jti).first():
            return jsonify({"error": "This bundle link was already used.", "retry_available": True}), 400

        session, error = get_valid_download_session(payload.get("download_session_id"))
        if not session:
            return jsonify({"error": f"Download session invalid: {error}", "retry_available": True}), 400

        files = EbookFile.query.filter_by(ebook_id=session.ebook_id).all()
        if not files:
            log_download_attempt(session.id, reason="bundle_files_missing")
            return jsonify({"error": "No files available to bundle.", "retry_available": True}), 404

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_item in files:
                path = Path(file_item.file_path)
                if path.exists():
                    zf.write(path, arcname=file_item.file_name)
                else:
                    log_download_attempt(session.id, file_id=file_item.id, reason="file_missing_in_bundle")
        zip_buffer.seek(0)

        db.session.add(DownloadTokenUse(token_jti=jti, download_session_id=session.id, file_id=None))
        log_download_attempt(session.id, file_id=None, success=True, completed=True)
        if session.user_id and files:
            newest = sorted(files, key=lambda x: x.created_at, reverse=True)[0]
            record_download_history(
                user_id=session.user_id,
                ebook_id=session.ebook_id,
                version_label=f"bundle:{newest.version_label}",
                code_id=session.code_id,
            )
        db.session.commit()
        filename = f"ebook-{session.ebook_id}-bundle.zip"
        return send_file(zip_buffer, as_attachment=True, download_name=filename, mimetype="application/zip")
    @app.post("/admin/codes/generate")
    @require_auth(role="admin")
    def admin_generate_code():
        data = as_data()
        ebook_id = data.get("ebook_id")
        ttl_hours = int(data.get("expires_in_hours") or 24)
        ebook = Ebook.query.get(ebook_id)
        if not ebook:
            return jsonify({"error": "Invalid ebook_id"}), 400
        code = AccessCode(
            code_value=create_access_code(),
            ebook_id=ebook.id,
            expires_at=utcnow() + timedelta(hours=ttl_hours),
            created_by_admin=request.current_user.id,
        )
        db.session.add(code)
        db.session.commit()
        log_admin_action(request.current_user.id, f"code_generate:{code.id}")
        return jsonify(
            {
                "id": code.id,
                "code_value": code.code_value,
                "ebook_id": code.ebook_id,
                "expires_at": code.expires_at.isoformat(),
                "is_used": code.is_used,
                "is_active": code.is_active,
            }
        ), 201

    @app.patch("/admin/codes/<int:code_id>/deactivate")
    @require_auth(role="admin")
    def admin_deactivate_code(code_id):
        code = AccessCode.query.get_or_404(code_id)
        code.is_active = False
        db.session.commit()
        log_admin_action(request.current_user.id, f"code_deactivate:{code.id}")
        return jsonify({"message": "Code deactivated"})

    @app.get("/admin/codes")
    @require_auth(role="admin")
    def admin_list_codes():
        ebook_id = request.args.get("ebook_id", type=int)
        status = (request.args.get("status") or "").strip().lower()
        query = AccessCode.query
        if ebook_id:
            query = query.filter_by(ebook_id=ebook_id)
        if status == "used":
            query = query.filter(AccessCode.is_used.is_(True))
        elif status == "active":
            query = query.filter(AccessCode.is_active.is_(True), AccessCode.expires_at >= utcnow())
        elif status == "expired":
            query = query.filter(AccessCode.expires_at < utcnow())
        codes = query.order_by(AccessCode.created_at.desc()).all()
        return jsonify(
            [
                {
                    "id": c.id,
                    "code_value": c.code_value,
                    "ebook_id": c.ebook_id,
                    "is_used": c.is_used,
                    "is_active": c.is_active,
                    "is_expired": c.expires_at < utcnow(),
                    "expires_at": c.expires_at.isoformat(),
                    "created_at": c.created_at.isoformat(),
                    "created_by_admin": c.created_by_admin,
                }
                for c in codes
            ]
        )

    @app.delete("/admin/codes/<int:code_id>")
    @require_auth(role="admin")
    def admin_delete_code(code_id):
        code = AccessCode.query.get_or_404(code_id)
        db.session.delete(code)
        db.session.commit()
        log_admin_action(request.current_user.id, f"code_delete:{code_id}")
        return jsonify({"message": "Code deleted"})

    @app.get("/admin/codes/usage-logs")
    @require_auth(role="admin")
    def admin_code_usage_logs():
        ebook_id = request.args.get("ebook_id", type=int)
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        query = CodeUsageLog.query
        if ebook_id:
            query = query.join(AccessCode, CodeUsageLog.code_id == AccessCode.id).filter(AccessCode.ebook_id == ebook_id)
        try:
            if start_date:
                query = query.filter(CodeUsageLog.used_at >= datetime.fromisoformat(start_date))
            if end_date:
                query = query.filter(CodeUsageLog.used_at <= datetime.fromisoformat(end_date))
        except ValueError:
            return jsonify({"error": "Invalid date format. Use ISO-8601."}), 400

        logs = query.order_by(CodeUsageLog.used_at.desc()).limit(500).all()
        return jsonify(
            [
                {
                    "id": log.id,
                    "code_id": log.code_id,
                    "user_id": log.user_id,
                    "ip_address": log.ip_address,
                    "device_info": log.device_info,
                    "used_at": log.used_at.isoformat(),
                    "download_completed": log.download_completed,
                    "was_successful": log.was_successful,
                    "failure_reason": log.failure_reason,
                }
                for log in logs
            ]
        )

    @app.get("/admin/codes/failed-attempts")
    @require_auth(role="admin")
    def admin_failed_code_attempts():
        rows = CodeAttempt.query.filter_by(successful=False).order_by(CodeAttempt.attempted_at.desc()).limit(500).all()
        return jsonify(
            [
                {
                    "id": row.id,
                    "session_key": row.session_key,
                    "ip_address": row.ip_address,
                    "attempted_at": row.attempted_at.isoformat(),
                }
                for row in rows
            ]
        )

    @app.get("/downloads/history")
    @require_auth()
    def download_history():
        rows = (
            DownloadHistory.query.filter_by(user_id=request.current_user.id)
            .order_by(DownloadHistory.downloaded_at.desc())
            .limit(200)
            .all()
        )
        payload = []
        for row in rows:
            ebook = Ebook.query.get(row.ebook_id)
            payload.append(
                {
                    "history_id": row.id,
                    "ebook_id": row.ebook_id,
                    "ebook_title": ebook.title if ebook else None,
                    "ebook_slug": ebook.slug if ebook else None,
                    "code_id": row.code_id,
                    "version_label": row.version_label,
                    "downloaded_at": row.downloaded_at.isoformat(),
                }
            )
        return jsonify(payload)

    @app.get("/admin/download-histories")
    @require_auth(role="admin")
    def admin_download_histories():
        user_id = request.args.get("user_id", type=int)
        ebook_id = request.args.get("ebook_id", type=int)
        query = DownloadHistory.query
        if user_id:
            query = query.filter(DownloadHistory.user_id == user_id)
        if ebook_id:
            query = query.filter(DownloadHistory.ebook_id == ebook_id)

        rows = query.order_by(DownloadHistory.downloaded_at.desc()).limit(1000).all()
        payload = []
        for row in rows:
            ebook = Ebook.query.get(row.ebook_id)
            payload.append(
                {
                    "history_id": row.id,
                    "user_id": row.user_id,
                    "ebook_id": row.ebook_id,
                    "ebook_title": ebook.title if ebook else None,
                    "ebook_slug": ebook.slug if ebook else None,
                    "code_id": row.code_id,
                    "version_label": row.version_label,
                    "downloaded_at": row.downloaded_at.isoformat(),
                }
            )
        return jsonify(payload)

    @app.get("/admin/download-failure-alerts")
    @require_auth(role="admin")
    def download_failure_alerts():
        window_start = utcnow() - timedelta(hours=24)
        total = DownloadAttemptLog.query.filter(DownloadAttemptLog.attempted_at >= window_start).count()
        failures = DownloadAttemptLog.query.filter(
            DownloadAttemptLog.attempted_at >= window_start,
            DownloadAttemptLog.was_successful.is_(False),
        ).count()
        failure_rate = (failures / total) if total else 0
        alert = failure_rate >= 0.3 and failures >= 10
        return jsonify(
            {
                "window": "24h",
                "total_attempts": total,
                "failed_attempts": failures,
                "failure_rate": round(failure_rate, 3),
                "alert": alert,
                "message": "Failure spike detected" if alert else "Failure rate normal",
            }
        )

    @app.get("/admin/dashboard/overview")
    @require_auth(role="admin")
    def admin_dashboard_overview():
        now = utcnow()
        total_ebooks = Ebook.query.count()
        total_active_codes = AccessCode.query.filter(AccessCode.is_active.is_(True), AccessCode.expires_at >= now).count()
        used_codes = AccessCode.query.filter(AccessCode.is_used.is_(True)).count()
        expired_codes = AccessCode.query.filter(AccessCode.expires_at < now).count()

        day_start = now - timedelta(days=1)
        week_start = now - timedelta(days=7)
        total_downloads_daily = DownloadEvent.query.filter(DownloadEvent.downloaded_at >= day_start).count()
        total_downloads_weekly = DownloadEvent.query.filter(DownloadEvent.downloaded_at >= week_start).count()
        total_downloads_all_time = DownloadEvent.query.count()

        top_ebook = (
            db.session.query(DownloadEvent.ebook_id, func.count(DownloadEvent.id).label("cnt"))
            .group_by(DownloadEvent.ebook_id)
            .order_by(func.count(DownloadEvent.id).desc())
            .first()
        )
        top_ebook_payload = None
        if top_ebook:
            eb = Ebook.query.get(top_ebook.ebook_id)
            top_ebook_payload = {"ebook_id": top_ebook.ebook_id, "title": eb.title if eb else None, "downloads": int(top_ebook.cnt)}

        line_chart = []
        for i in range(13, -1, -1):
            day = (now - timedelta(days=i)).date()
            next_day = day + timedelta(days=1)
            count = DownloadEvent.query.filter(DownloadEvent.downloaded_at >= datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc), DownloadEvent.downloaded_at < datetime.combine(next_day, datetime.min.time(), tzinfo=timezone.utc)).count()
            line_chart.append({"date": day.isoformat(), "downloads": count})

        bar_chart = []
        rows = (
            db.session.query(DownloadEvent.ebook_id, func.count(DownloadEvent.id).label("cnt"))
            .group_by(DownloadEvent.ebook_id)
            .order_by(func.count(DownloadEvent.id).desc())
            .limit(10)
            .all()
        )
        for row in rows:
            eb = Ebook.query.get(row.ebook_id)
            bar_chart.append({"ebook_id": row.ebook_id, "title": eb.title if eb else None, "downloads": int(row.cnt)})

        total_codes = AccessCode.query.count()
        pie = {
            "active": total_active_codes,
            "used": used_codes,
            "expired": expired_codes,
            "inactive": max(total_codes - total_active_codes - used_codes - expired_codes, 0),
        }

        recent_activity = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
        return jsonify(
            {
                "totals": {
                    "ebooks": total_ebooks,
                    "active_codes": total_active_codes,
                    "used_codes": used_codes,
                    "expired_codes": expired_codes,
                    "downloads_daily": total_downloads_daily,
                    "downloads_weekly": total_downloads_weekly,
                    "downloads_all_time": total_downloads_all_time,
                },
                "most_downloaded_ebook": top_ebook_payload,
                "charts": {"line_downloads": line_chart, "bar_top_ebooks": bar_chart, "pie_code_status": pie},
                "recent_activity": [
                    {
                        "admin_user_id": a.admin_user_id,
                        "action": a.action,
                        "ip_address": a.ip_address,
                        "created_at": a.created_at.isoformat(),
                    }
                    for a in recent_activity
                ],
            }
        )

    @app.get("/admin/ebooks")
    @require_auth(role="admin")
    def admin_list_ebooks_panel():
        q = (request.args.get("q") or "").strip().lower()
        category_id = request.args.get("category_id", type=int)
        featured = request.args.get("featured")
        query = Ebook.query
        if q:
            query = query.filter((func.lower(Ebook.title).contains(q)) | (func.lower(Ebook.author).contains(q)))
        if category_id:
            query = query.filter(Ebook.category_id == category_id)
        if featured is not None:
            query = query.filter(Ebook.is_featured.is_(str(featured).lower() == "true"))
        ebooks = query.order_by(Ebook.updated_at.desc()).all()
        return jsonify([ebook_to_dict(e, include_files=True, include_stats=True) for e in ebooks])

    @app.get("/admin/users")
    @require_auth(role="admin")
    def admin_users():
        users = User.query.order_by(User.created_at.desc()).all()
        return jsonify([
            {
                "id": u.id,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat(),
                "review_count": Review.query.filter_by(user_id=u.id).count(),
                "download_count": DownloadHistory.query.filter_by(user_id=u.id).count(),
            }
            for u in users
        ])

    @app.patch("/admin/users/<int:user_id>/deactivate")
    @require_auth(role="admin")
    def admin_deactivate_user(user_id):
        user = User.query.get_or_404(user_id)
        user.is_active = False
        Session.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        log_admin_action(request.current_user.id, f"user_deactivate:{user.id}")
        return jsonify({"message": "User deactivated"})

    def _csv_response(filename, headers, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.get("/admin/exports/downloads.csv")
    @require_auth(role="admin")
    def export_downloads_csv():
        rows = DownloadHistory.query.order_by(DownloadHistory.downloaded_at.desc()).all()
        return _csv_response(
            "downloads.csv",
            ["history_id", "user_id", "ebook_id", "code_id", "version_label", "downloaded_at"],
            [[r.id, r.user_id, r.ebook_id, r.code_id, r.version_label, r.downloaded_at.isoformat()] for r in rows],
        )

    @app.get("/admin/exports/code-usage.csv")
    @require_auth(role="admin")
    def export_code_usage_csv():
        rows = CodeUsageLog.query.order_by(CodeUsageLog.used_at.desc()).all()
        return _csv_response(
            "code_usage.csv",
            ["id", "code_id", "user_id", "ip_address", "used_at", "download_completed", "was_successful", "failure_reason"],
            [[r.id, r.code_id, r.user_id, r.ip_address, r.used_at.isoformat(), r.download_completed, r.was_successful, r.failure_reason] for r in rows],
        )

    @app.get("/admin/exports/user-activity.csv")
    @require_auth(role="admin")
    def export_user_activity_csv():
        users = User.query.order_by(User.created_at.desc()).all()
        return _csv_response(
            "user_activity.csv",
            ["user_id", "email", "role", "is_active", "reviews", "favorites", "downloads"],
            [[u.id, u.email, u.role, u.is_active, Review.query.filter_by(user_id=u.id).count(), Favorite.query.filter_by(user_id=u.id).count(), DownloadHistory.query.filter_by(user_id=u.id).count()] for u in users],
        )

    @app.get("/admin/reports/summary")
    @require_auth(role="admin")
    def admin_report_summary():
        period = (request.args.get("period") or "daily").strip().lower()
        days = 1 if period == "daily" else 7
        since = utcnow() - timedelta(days=days)
        summary = {
            "period": period,
            "downloads": DownloadHistory.query.filter(DownloadHistory.downloaded_at >= since).count(),
            "new_codes": AccessCode.query.filter(AccessCode.created_at >= since).count(),
            "new_reviews": Review.query.filter(Review.created_at >= since).count(),
            "new_users": User.query.filter(User.created_at >= since).count(),
        }
        return jsonify(summary)

    @app.post("/admin/reports/send")
    @require_auth(role="admin")
    def admin_send_report_preview():
        period = (request.args.get("period") or "daily").strip().lower()
        days = 1 if period == "daily" else 7
        since = utcnow() - timedelta(days=days)
        payload = {
            "period": period,
            "generated_at": utcnow().isoformat(),
            "downloads": DownloadHistory.query.filter(DownloadHistory.downloaded_at >= since).count(),
            "codes_used": AccessCode.query.filter(AccessCode.is_used.is_(True), AccessCode.created_at >= since).count(),
            "top_ebook": None,
        }
        top = (
            db.session.query(DownloadHistory.ebook_id, func.count(DownloadHistory.id).label("cnt"))
            .filter(DownloadHistory.downloaded_at >= since)
            .group_by(DownloadHistory.ebook_id)
            .order_by(func.count(DownloadHistory.id).desc())
            .first()
        )
        if top:
            eb = Ebook.query.get(top.ebook_id)
            payload["top_ebook"] = {"ebook_id": top.ebook_id, "title": eb.title if eb else None, "downloads": int(top.cnt)}
        log_admin_action(request.current_user.id, f"report_send:{period}")
        return jsonify({"message": "Report generated (email integration placeholder)", "report": payload})

    @app.get("/admin/staging")
    @require_auth(role="admin")
    def get_staging_status():
        enabled = get_setting("staging_mode", "false").lower() == "true"
        return jsonify({"staging_mode": enabled, "env_default": app.config["ENABLE_STAGING_MODE"]})

    @app.post("/admin/staging/toggle")
    @require_auth(role="admin")
    def toggle_staging_mode():
        data = as_data()
        enabled = str((data.get("enabled") if data else "false")).lower() == "true"
        set_setting("staging_mode", str(enabled).lower())
        log_admin_action(request.current_user.id, f"staging_toggle:{enabled}")
        return jsonify({"staging_mode": enabled})

    @app.post("/admin/maintenance/toggle")
    @require_auth(role="admin")
    def toggle_maintenance_mode():
        data = as_data()
        enabled = str((data.get("enabled") if data else "true")).lower() == "true"
        disable_downloads = str((data.get("disable_downloads") if data else "true")).lower() == "true"
        disable_code_entry = str((data.get("disable_code_entry") if data else "true")).lower() == "true"
        lockdown = str((data.get("lockdown") if data else "false")).lower() == "true"
        message = (data.get("message") if data else None) or "Maintenance in progress"

        set_setting("maintenance_mode", str(enabled).lower())
        set_setting("maintenance_disable_downloads", str(disable_downloads).lower())
        set_setting("maintenance_disable_code_entry", str(disable_code_entry).lower())
        set_setting("maintenance_lockdown", str(lockdown).lower())
        set_setting("maintenance_message", message)

        log_admin_action(request.current_user.id, f"maintenance_toggle:{enabled}:downloads={disable_downloads}:codes={disable_code_entry}:lockdown={lockdown}")
        return jsonify(
            {
                "maintenance_mode": enabled,
                "disable_downloads": disable_downloads,
                "disable_code_entry": disable_code_entry,
                "lockdown": lockdown,
                "message": message,
            }
        )

    @app.post("/admin/notifications")
    @require_auth(role="admin")
    def create_notification():
        data = as_data()
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"error": "message is required"}), 400
        row = SiteNotification(message=message, is_active=True, created_by_admin=request.current_user.id)
        db.session.add(row)
        set_setting("site_notification", message)
        db.session.commit()
        log_admin_action(request.current_user.id, f"notification_create:{row.id}")
        return jsonify({"id": row.id, "message": row.message, "is_active": row.is_active}), 201

    @app.get("/admin/notifications")
    @require_auth(role="admin")
    def list_notifications():
        rows = SiteNotification.query.order_by(SiteNotification.created_at.desc()).all()
        return jsonify([
            {
                "id": r.id,
                "message": r.message,
                "is_active": r.is_active,
                "created_by_admin": r.created_by_admin,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ])

    @app.post("/admin/backups/trigger")
    @require_auth(role="admin")
    def trigger_backup():
        backup_root = Path(storage_root) / "backups"
        backup_root.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().strftime("%Y%m%d%H%M%S")
        backup_file = backup_root / f"backup-{stamp}.json"
        snapshot = {
            "generated_at": utcnow().isoformat(),
            "counts": {
                "users": User.query.count(),
                "ebooks": Ebook.query.count(),
                "codes": AccessCode.query.count(),
                "downloads": DownloadHistory.query.count(),
                "reviews": Review.query.count(),
            },
        }
        backup_file.write_text(json.dumps(snapshot, indent=2))
        job = BackupJob(initiated_by_admin=request.current_user.id, backup_file=str(backup_file), status="completed")
        db.session.add(job)
        db.session.commit()
        log_admin_action(request.current_user.id, f"backup_trigger:{job.id}")
        return jsonify({"job_id": job.id, "backup_file": str(backup_file), "status": job.status})

    @app.get("/admin/backups")
    @require_auth(role="admin")
    def list_backups():
        jobs = BackupJob.query.order_by(BackupJob.created_at.desc()).limit(100).all()
        return jsonify([
            {
                "id": j.id,
                "initiated_by_admin": j.initiated_by_admin,
                "backup_file": j.backup_file,
                "status": j.status,
                "created_at": j.created_at.isoformat(),
            }
            for j in jobs
        ])

    @app.get("/admin/error-logs")
    @require_auth(role="admin")
    def list_error_logs():
        rows = ErrorLog.query.order_by(ErrorLog.created_at.desc()).limit(500).all()
        return jsonify([
            {
                "id": r.id,
                "source": r.source,
                "severity": r.severity,
                "message": r.message,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ])

    @app.post("/admin/error-logs")
    @require_auth(role="admin")
    def create_error_log_entry():
        data = as_data()
        msg = (data.get("message") or "").strip()
        if not msg:
            return jsonify({"error": "message is required"}), 400
        row = ErrorLog(source=(data.get("source") or "manual").strip(), severity=(data.get("severity") or "error").strip(), message=msg)
        db.session.add(row)
        db.session.commit()
        log_admin_action(request.current_user.id, f"error_log_create:{row.id}")
        return jsonify({"id": row.id}), 201

    @app.get("/admin/security-events")
    @require_auth(role="admin")
    def admin_security_events():
        rows = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(500).all()
        return jsonify(
            [
                {
                    "id": r.id,
                    "event_type": r.event_type,
                    "severity": r.severity,
                    "ip_address": r.ip_address,
                    "user_id": r.user_id,
                    "details": r.details,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]
        )

    @app.post("/admin/backups/schedule")
    @require_auth(role="admin")
    def schedule_backup():
        data = as_data()
        frequency = (data.get("frequency") or "daily").strip().lower()
        if frequency not in {"daily", "weekly"}:
            return jsonify({"error": "frequency must be daily or weekly"}), 400
        set_setting("backup_schedule", frequency)
        log_admin_action(request.current_user.id, f"backup_schedule:{frequency}")
        return jsonify({"message": "Backup schedule updated", "frequency": frequency})

    @app.post("/admin/automation/cleanup")
    @require_auth(role="admin")
    def run_automation_cleanup():
        cutoff = utcnow() - timedelta(days=app.config["SECURITY_LOG_RETENTION_DAYS"])

        expired_codes_deleted = AccessCode.query.filter(AccessCode.expires_at < utcnow(), AccessCode.is_used.is_(False)).delete()
        old_security_events = SecurityEvent.query.filter(SecurityEvent.created_at < cutoff).delete()
        old_error_logs = ErrorLog.query.filter(ErrorLog.created_at < cutoff).delete()
        old_login_attempts = LoginAttempt.query.filter(LoginAttempt.attempted_at < cutoff).delete()
        old_code_attempts = CodeAttempt.query.filter(CodeAttempt.attempted_at < cutoff).delete()
        old_review_attempts = ReviewAttemptLog.query.filter(ReviewAttemptLog.attempted_at < cutoff).delete()
        old_reset_attempts = PasswordResetAttempt.query.filter(PasswordResetAttempt.attempted_at < cutoff).delete()

        db.session.commit()
        log_admin_action(request.current_user.id, "automation_cleanup_run")
        return jsonify(
            {
                "expired_unused_codes_removed": int(expired_codes_deleted or 0),
                "old_security_events_removed": int(old_security_events or 0),
                "old_error_logs_removed": int(old_error_logs or 0),
                "old_login_attempts_removed": int(old_login_attempts or 0),
                "old_code_attempts_removed": int(old_code_attempts or 0),
                "old_review_attempts_removed": int(old_review_attempts or 0),
                "old_password_reset_attempts_removed": int(old_reset_attempts or 0),
                "retention_days": app.config["SECURITY_LOG_RETENTION_DAYS"],
            }
        )

    @app.get("/admin/settings/rate-limits")
    @require_auth(role="admin")
    def get_rate_limits():
        return jsonify(
            {
                "login_window_minutes": app.config["LOGIN_RATE_LIMIT_WINDOW_MINUTES"],
                "login_max_attempts": app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"],
                "code_window_minutes": app.config["CODE_ATTEMPT_WINDOW_MINUTES"],
                "code_max_attempts": app.config["CODE_ATTEMPT_MAX"],
                "review_window_minutes": app.config["REVIEW_RATE_LIMIT_WINDOW_MINUTES"],
                "review_max_attempts": app.config["REVIEW_RATE_LIMIT_MAX_ATTEMPTS"],
            }
        )

    @app.get("/sitemap.xml")
    def sitemap_xml():
        pages = ["/", "/ebooks", "/categories", "/admin"]
        categories = Category.query.all()
        ebooks = Ebook.query.filter_by(is_active=True).all()
        urls = pages + [f"/categories/{c.slug}/ebooks" for c in categories] + [f"/ebook/{e.slug or e.id}" for e in ebooks]
        xml = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        for u in urls:
            xml.append("<url><loc>" + escape(u) + "</loc></url>")
        xml.append("</urlset>")
        return Response("".join(xml), mimetype="application/xml")

    @app.get("/admin/search-analytics")
    @require_auth(role="admin")
    def admin_search_analytics():
        rows = (
            db.session.query(SearchQueryLog.term, func.count(SearchQueryLog.id).label("cnt"))
            .group_by(SearchQueryLog.term)
            .order_by(func.count(SearchQueryLog.id).desc())
            .limit(20)
            .all()
        )
        zero_rows = (
            db.session.query(SearchQueryLog.term, func.count(SearchQueryLog.id).label("cnt"))
            .filter(SearchQueryLog.is_zero_result.is_(True))
            .group_by(SearchQueryLog.term)
            .order_by(func.count(SearchQueryLog.id).desc())
            .limit(20)
            .all()
        )
        return jsonify(
            {
                "most_searched_terms": [{"term": q, "count": int(c)} for q, c in rows],
                "zero_result_searches": [{"term": q, "count": int(c)} for q, c in zero_rows],
                "total_queries": SearchQueryLog.query.count(),
            }
        )

    @app.get("/admin/download-counts")
    @require_auth(role="admin")
    def admin_download_counts():
        rows = (
            db.session.query(DownloadEvent.ebook_id, func.count(DownloadEvent.id))
            .group_by(DownloadEvent.ebook_id)
            .all()
        )
        out = []
        for ebook_id, count in rows:
            ebook = Ebook.query.get(ebook_id)
            if ebook:
                out.append({"ebook_id": ebook.id, "title": ebook.title, "download_count": count})
        return jsonify(out)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
