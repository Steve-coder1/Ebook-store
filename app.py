import io
import os
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, make_response, render_template, request, send_file
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

    project_root = Path(__file__).resolve().parent
    storage_root = Path(os.getenv("PRIVATE_STORAGE_ROOT", project_root / "private_storage")).resolve()
    files_root = storage_root / "ebooks"
    previews_root = storage_root / "previews"
    files_root.mkdir(parents=True, exist_ok=True)
    previews_root.mkdir(parents=True, exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()

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

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/admin")
    def admin_page():
        return render_template("admin.html")

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
            return jsonify({"error": "Too many login attempts. Try later."}), 429

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            record_login_attempt(email, False)
            return jsonify({"error": "Invalid credentials"}), 401

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
            return jsonify({"error": "Too many login attempts. Try later."}), 429

        user = User.query.filter_by(email=email, role="admin").first()
        if not user or not check_password_hash(user.password_hash, password):
            record_login_attempt(email, False)
            return jsonify({"error": "Invalid admin credentials"}), 401

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
            is_featured=str(data.get("is_featured", "false")).lower() == "true",
            is_active=True,
        )
        db.session.add(ebook)
        db.session.commit()
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
            return jsonify({"message": "ebook deleted"})

        ebook.is_active = False
        db.session.commit()
        return jsonify({"message": "ebook deactivated"})

    @app.get("/ebooks")
    def list_ebooks():
        category_slug = (request.args.get("category") or "").strip()
        q = (request.args.get("q") or "").strip().lower()
        featured = (request.args.get("featured") or "").strip().lower() == "true"

        query = Ebook.query.filter_by(is_active=True)
        if category_slug:
            category = Category.query.filter_by(slug=category_slug).first()
            if not category:
                return jsonify([])
            query = query.filter_by(category_id=category.id)
        if featured:
            query = query.filter_by(is_featured=True)
        if q:
            query = query.filter(
                (func.lower(Ebook.title).contains(q))
                | (func.lower(Ebook.author).contains(q))
                | (func.lower(Ebook.description).contains(q))
            )

        ebooks = query.order_by(Ebook.created_at.desc()).all()
        return jsonify([ebook_to_dict(e, include_files=True) for e in ebooks])

    @app.get("/ebooks/<int:ebook_id>")
    def ebook_detail(ebook_id):
        ebook = Ebook.query.get_or_404(ebook_id)
        if not ebook.is_active:
            abort(404)
        return jsonify(ebook_to_dict(ebook, include_files=True))

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
        ids = [f.ebook_id for f in Favorite.query.filter_by(user_id=request.current_user.id).all()]
        ebooks = Ebook.query.filter(Ebook.id.in_(ids), Ebook.is_active.is_(True)).all() if ids else []
        return jsonify([ebook_to_dict(e, include_files=False) for e in ebooks])

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
        db.session.commit()
        return send_file(file_path, as_attachment=True, download_name=file_item.file_name)

    @app.get("/codes/captcha")
    def code_captcha():
        challenge, answer = generate_captcha_pair()
        return jsonify({"challenge": challenge, "answer_token": answer})

    @app.post("/codes/validate")
    def validate_code():
        if code_attempts_exceeded():
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
        return jsonify({"message": "Code deactivated"})

    @app.get("/admin/codes")
    @require_auth(role="admin")
    def admin_list_codes():
        ebook_id = request.args.get("ebook_id", type=int)
        query = AccessCode.query
        if ebook_id:
            query = query.filter_by(ebook_id=ebook_id)
        codes = query.order_by(AccessCode.created_at.desc()).all()
        return jsonify(
            [
                {
                    "id": c.id,
                    "code_value": c.code_value,
                    "ebook_id": c.ebook_id,
                    "is_used": c.is_used,
                    "is_active": c.is_active,
                    "expires_at": c.expires_at.isoformat(),
                    "created_at": c.created_at.isoformat(),
                    "created_by_admin": c.created_by_admin,
                }
                for c in codes
            ]
        )

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
        rows = DownloadEvent.query.filter_by(user_id=request.current_user.id).order_by(DownloadEvent.downloaded_at.desc()).limit(200).all()
        return jsonify(
            [
                {
                    "ebook_id": row.ebook_id,
                    "file_id": row.ebook_file_id,
                    "downloaded_at": row.downloaded_at.isoformat(),
                }
                for row in rows
            ]
        )

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
