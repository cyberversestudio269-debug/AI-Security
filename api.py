import hashlib
import hmac
import io
import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from urllib.parse import urlunsplit

from fastapi import BackgroundTasks, Cookie, Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, create_engine, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker

import report_generator
import scanner
from target_security import (
    UnsafeTargetError,
    challenge_digest,
    parse_public_https_url,
    verify_dns_challenge,
    verify_file_challenge,
)


LOGGER = logging.getLogger("ai_risk_scanner")
BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
SESSION_COOKIE_NAME = "ai_risk_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
SESSION_COOKIE_SECURE = APP_ENV in ("staging", "production")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./ai_risk_scanner.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_options = {}
if DATABASE_URL.startswith("sqlite:"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class LoginSession(Base):
    __tablename__ = "login_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    host = Column(String(253), nullable=False)
    port = Column(Integer, nullable=False)
    model = Column(String(200), nullable=False, default="default")
    challenge_hash = Column(String(64), nullable=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    target_url = Column(String(2048), nullable=True)
    company_name = Column(String(120), nullable=False)
    questionnaire = Column(JSON, nullable=False)
    status = Column(String(16), nullable=False, default="queued", index=True)
    result_json = Column(JSON, nullable=True)
    error_message = Column(String(300), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)


class AccountInput(BaseModel):
    email: str
    password: str

    @validator("email")
    def normalize_email(cls, value):
        value = value.strip().lower()
        if len(value) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Enter a valid email address.")
        return value

    @validator("password")
    def validate_password(cls, value):
        if len(value) < 12 or len(value) > 256:
            raise ValueError("Password must be between 12 and 256 characters.")
        return value


class TargetInput(BaseModel):
    url: str
    model: str = "default"

    @validator("url")
    def validate_url_length(cls, value):
        if len(value) > 2048:
            raise ValueError("Target URL is too long.")
        return value.strip()

    @validator("model")
    def validate_model(cls, value):
        value = value.strip()
        if not value or len(value) > 200:
            raise ValueError("Model name must be between 1 and 200 characters.")
        return value


class Questionnaire(BaseModel):
    uses_personal_data: bool = False
    has_human_review: bool = False
    has_role_based_access: bool = False
    has_retention_policy: bool = False
    discloses_ai_use: bool = False


class VerificationInput(BaseModel):
    method: str

    @validator("method")
    def validate_method(cls, value):
        if value not in ("dns", "file"):
            raise ValueError("Verification method must be 'dns' or 'file'.")
        return value


class ScanInput(BaseModel):
    target_id: Optional[int] = None
    demo: bool = False
    authorized: bool = False
    target_api_key: Optional[str] = None
    company_name: str = "Client"
    questionnaire: Questionnaire = Field(default_factory=Questionnaire)

    @validator("target_api_key")
    def validate_api_key(cls, value):
        if value is not None and (len(value) > 4096 or not value.strip()):
            raise ValueError("Target API key must be non-empty and at most 4096 characters.")
        return value

    @validator("company_name")
    def validate_company_name(cls, value):
        value = value.strip()
        if not value or len(value) > 120:
            raise ValueError("Company name must be between 1 and 120 characters.")
        return value


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32
    )
    return "%s$%s" % (salt.hex(), digest.hex())


def _password_matches(password, encoded):
    try:
        salt_hex, expected = encoded.split("$", 1)
        candidate = _password_hash(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def _new_session(db, user, response):
    token = secrets.token_urlsafe(32)
    login = LoginSession(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
    )
    db.add(login)
    db.commit()
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "expires_in": SESSION_TTL_SECONDS}


def current_user(
    session_cookie: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db=Depends(get_db),
):
    if session_cookie is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    token_hash = hashlib.sha256(session_cookie.encode("utf-8")).hexdigest()
    login = db.query(LoginSession).filter(LoginSession.token_hash == token_hash).first()
    if login is None or login.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.")
    user = db.query(User).filter(User.id == login.user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return user


def _owned_target(db, user_id, target_id):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == user_id)
        .first()
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target


def _scan_response(scan, include_result=False):
    data = {
        "id": scan.id,
        "target_id": scan.target_id,
        "status": scan.status,
        "company_name": scan.company_name,
        "questionnaire": scan.questionnaire,
        "created_at": scan.created_at.isoformat() + "Z",
        "finished_at": scan.finished_at.isoformat() + "Z" if scan.finished_at else None,
        "error": scan.error_message,
    }
    if include_result:
        data["result"] = scan.result_json
    elif scan.result_json:
        data["summary"] = scan.result_json.get("summary")
    return data


def execute_scan_job(scan_id, target_url, target_model, target_api_key, demo, questionnaire):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            LOGGER.error("Scan %s disappeared before execution.", scan_id)
            return
        scan.status = "running"
        db.commit()

        config = SimpleNamespace(
            target_url=target_url,
            target_model=target_model,
            target_api_key=target_api_key,
            system_prompt=None,
            demo=demo,
            heuristic_judge=demo,
            judge_model=os.environ.get("JUDGE_MODEL", scanner.DEFAULT_JUDGE_MODEL),
            only=None,
            limit=None,
            repeat=None,
            delay=0 if demo else 0.5,
            safe_public_target=not demo,
        )
        library = scanner.load_library(str(BASE_DIR / "attack_library_v0.1.json"))
        results = scanner.run_scan(config, library)
        score = scanner.risk_score(results)
        summary = {
            "risk_score": score,
            "risk_level": scanner.risk_level(score),
            "tests_run": len(results),
            "failed": sum(1 for item in results if item["result"] == "FAIL"),
            "needs_review": sum(1 for item in results if item["result"] == "REVIEW"),
            "errors": sum(1 for item in results if item["result"] == "ERROR"),
            "demo_mode": demo,
        }

        scan.result_json = {
            "summary": summary,
            "results": results,
            "questionnaire": questionnaire,
        }
        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        db.commit()
    except Exception:
        LOGGER.exception("Scan %s failed.", scan_id)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is not None:
            scan.status = "failed"
            scan.error_message = "The scan failed. Contact the administrator with the scan ID."
            scan.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


app = FastAPI(title="AI Risk Scanner", version="0.2.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web")), name="static")


def validate_production_configuration(
    app_env, database_url, cookie_secure, judge_api_key
):
    if app_env not in ("development", "test", "staging", "production"):
        raise RuntimeError("APP_ENV must be development, test, staging, or production.")
    if app_env != "production":
        return
    if database_url.startswith("sqlite:"):
        raise RuntimeError("Production requires PostgreSQL; SQLite is for local development only.")
    if not cookie_secure:
        raise RuntimeError("Production requires secure session cookies.")
    if not judge_api_key:
        raise RuntimeError("Production requires ANTHROPIC_API_KEY for live scans.")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.on_event("startup")
def create_tables():
    validate_production_configuration(
        APP_ENV,
        DATABASE_URL,
        SESSION_COOKIE_SECURE,
        os.environ.get("ANTHROPIC_API_KEY"),
    )
    Base.metadata.create_all(bind=engine)


@app.get("/", response_class=FileResponse)
def home():
    return FileResponse(str(BASE_DIR / "web" / "index.html"))


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: AccountInput, response: Response, db=Depends(get_db)):
    user = User(email=payload.email, password_hash=_password_hash(payload.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    db.refresh(user)
    return _new_session(db, user, response)


@app.post("/api/auth/login")
def login(payload: AccountInput, response: Response, db=Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not _password_matches(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return _new_session(db, user, response)


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    session_cookie: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db=Depends(get_db),
):
    if session_cookie is not None:
        token_hash = hashlib.sha256(session_cookie.encode("utf-8")).hexdigest()
        db.query(LoginSession).filter(LoginSession.token_hash == token_hash).delete()
        db.commit()
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"id": user.id, "email": user.email}


@app.delete("/api/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    response: Response,
    user=Depends(current_user),
    db=Depends(get_db),
):
    active_scans = (
        db.query(func.count(Scan.id))
        .filter(
            Scan.owner_id == user.id,
            Scan.status.in_(("queued", "running")),
        )
        .scalar()
    )
    if active_scans:
        raise HTTPException(
            status_code=409,
            detail="Wait for active scans to finish before deleting this account.",
        )

    db.query(Scan).filter(Scan.owner_id == user.id).delete(synchronize_session=False)
    db.query(Target).filter(Target.owner_id == user.id).delete(synchronize_session=False)
    db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
    db.delete(user)
    db.commit()
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.post("/api/targets", status_code=status.HTTP_201_CREATED)
def create_target(payload: TargetInput, user=Depends(current_user), db=Depends(get_db)):
    count = db.query(func.count(Target.id)).filter(Target.owner_id == user.id).scalar()
    if count >= 10:
        raise HTTPException(status_code=429, detail="This account has reached the 10-target limit.")
    try:
        parsed, host, port, _ = parse_public_https_url(payload.url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    netloc = host if port == 443 else "%s:%d" % (host, port)
    normalized_url = urlunsplit(("https", netloc, parsed.path or "/", "", ""))
    challenge = secrets.token_urlsafe(32)
    target = Target(
        owner_id=user.id,
        url=normalized_url,
        host=host,
        port=port,
        model=payload.model,
        challenge_hash=challenge_digest(challenge),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return {
        "id": target.id,
        "url": target.url,
        "model": target.model,
        "verified": False,
        "verification_token": challenge,
        "dns_record": {
            "name": "_ai-risk-scanner.%s" % host,
            "type": "TXT",
            "value": challenge,
        },
        "file_path": "/.well-known/ai-risk-scanner-verification.txt",
        "file_contents": challenge,
    }


@app.get("/api/targets")
def list_targets(user=Depends(current_user), db=Depends(get_db)):
    targets = (
        db.query(Target)
        .filter(Target.owner_id == user.id)
        .order_by(Target.created_at.desc())
        .all()
    )
    return [
        {
            "id": item.id,
            "url": item.url,
            "model": item.model,
            "verified": item.verified_at is not None,
            "verified_at": item.verified_at.isoformat() + "Z" if item.verified_at else None,
            "created_at": item.created_at.isoformat() + "Z",
        }
        for item in targets
    ]


@app.post("/api/targets/{target_id}/verify")
def verify_target(
    target_id: int,
    payload: VerificationInput,
    user=Depends(current_user),
    db=Depends(get_db),
):
    method = payload.method
    target = _owned_target(db, user.id, target_id)
    try:
        parse_public_https_url(target.url)
        if method == "dns":
            verified = verify_dns_challenge(target.host, target.challenge_hash)
        else:
            verified = verify_file_challenge(
                target.host, target.port, target.challenge_hash
            )
    except (UnsafeTargetError, OSError, UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Target verification could not complete.") from exc
    if not verified:
        raise HTTPException(status_code=400, detail="The verification challenge was not found.")
    target.verified_at = datetime.utcnow()
    db.commit()
    return {"id": target.id, "verified": True}


@app.post("/api/scans", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: ScanInput,
    background_tasks: BackgroundTasks,
    user=Depends(current_user),
    db=Depends(get_db),
):
    target = None
    target_url = None
    target_model = "demo"
    if payload.demo:
        if payload.target_id is not None or payload.target_api_key:
            raise HTTPException(status_code=400, detail="Demo scans do not accept target credentials.")
    else:
        if not payload.authorized:
            raise HTTPException(
                status_code=400,
                detail="Confirm that you own or are authorized to test this chatbot.",
            )
        if payload.target_id is None:
            raise HTTPException(status_code=400, detail="Choose a verified target.")
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise HTTPException(
                status_code=503,
                detail="Live scans require ANTHROPIC_API_KEY to be configured on the server.",
            )
        target = _owned_target(db, user.id, payload.target_id)
        if target.verified_at is None:
            raise HTTPException(status_code=403, detail="Verify target ownership before scanning.")
        try:
            parse_public_https_url(target.url)
        except UnsafeTargetError as exc:
            raise HTTPException(status_code=400, detail="Target is no longer publicly reachable.") from exc
        target_url = target.url
        target_model = target.model

    running = (
        db.query(func.count(Scan.id))
        .filter(Scan.owner_id == user.id, Scan.status.in_(("queued", "running")))
        .scalar()
    )
    if running:
        raise HTTPException(status_code=429, detail="Wait for the current scan to finish.")

    scan = Scan(
        owner_id=user.id,
        target_id=target.id if target else None,
        target_url=target_url,
        company_name=payload.company_name,
        questionnaire=payload.questionnaire.dict(),
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(
        execute_scan_job,
        scan.id,
        target_url,
        target_model,
        payload.target_api_key,
        payload.demo,
        payload.questionnaire.dict(),
    )
    return _scan_response(scan)


@app.get("/api/scans")
def list_scans(user=Depends(current_user), db=Depends(get_db)):
    scans = (
        db.query(Scan)
        .filter(Scan.owner_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )
    return [_scan_response(item) for item in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, user=Depends(current_user), db=Depends(get_db)):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.owner_id == user.id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _scan_response(scan, include_result=True)


@app.get("/api/scans/{scan_id}/report.pdf")
def download_report(scan_id: int, user=Depends(current_user), db=Depends(get_db)):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.owner_id == user.id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=409, detail="The scan report is not ready.")
    output = io.BytesIO()
    report_generator.build_report(scan.result_json, output, scan.company_name)
    return Response(
        content=output.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="scan-%d.pdf"' % scan.id},
    )
