"""
Flo Permit - South Florida Permit Checker API
Production-ready FastAPI backend with user authentication and profiles
"""

import os
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

SENTRY_DSN = os.getenv("SENTRY_DSN")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FastApiIntegration(), SqlalchemyIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment=os.getenv("ENVIRONMENT", "production"),
    )

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    Form,
    Request,
    Depends,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
import os
import tempfile
import shutil
import uuid
import re
import json
import traceback
import resend
import stripe
from datetime import datetime
from typing import Optional, List
from dotenv import load_dotenv

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

load_dotenv()

from reader import get_document_text
from permit_data import get_permit_requirements, get_city_key, get_permit_types
from analyzer import analyze_document_with_claude

from auth import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    get_current_user_id,
    generate_reset_token,
    get_reset_token_expiry,
    is_token_expired,
)

# ============================================================================
# EMAIL CONFIGURATION
# ============================================================================

resend.api_key = os.getenv("RESEND_API_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://flopermit.vercel.app")

# ============================================================================
# STRIPE CONFIGURATION
# ============================================================================

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICES = {
    "pro": "price_1StYmAF8sW0Jp8OD2qc8v7d4",
    "business": "price_1StYmUF8sW0Jp8ODrL2fEoQB",
}
TIER_LIMITS = {
    "free": 3,
    "pro": 50,
    "business": 999999,  # unlimited
}

# ============================================================================
# DATABASE SETUP
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./permitpro.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# DATABASE MODELS
# ============================================================================


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    company_name = Column(String(255))
    phone = Column(String(50))
    is_active = Column(Boolean, default=True)
    subscription_tier = Column(String(50), default="free")
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    subscription_ends_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    analyses = relationship(
        "AnalysisHistory",
        back_populates="user",
        order_by="desc(AnalysisHistory.created_at)",
    )
    reset_tokens = relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class AnalysisHistory(Base):
    __tablename__ = "analysis_history"

    id = Column(Integer, primary_key=True, index=True)
    analysis_uuid = Column(String(36), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    city = Column(String(100), nullable=False)
    permit_type = Column(String(100), nullable=False)
    files_analyzed = Column(Integer, default=0)
    total_size_bytes = Column(Integer)
    overall_status = Column(String(50))
    compliance_score = Column(Integer)
    file_list = Column(Text)
    analysis_data = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="analyses")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reset_tokens")


class APILog(Base):
    __tablename__ = "api_logs"

    id = Column(Integer, primary_key=True, index=True)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    response_time_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)
print("✅ Database tables initialized")


# Migrate: Add Stripe columns if they don't exist
def migrate_database():
    from sqlalchemy import text, inspect

    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("users")]

    if "stripe_customer_id" not in columns:
        print("📦 Adding Stripe columns to users table...")
        for col_sql in [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_ends_at TIMESTAMP",
        ]:
            try:
                with engine.begin() as conn:
                    conn.execute(text(col_sql))
            except Exception as e:
                print(f"⚠️ Column add note: {e}")
        print("✅ Stripe columns migration complete")
    else:
        print("✅ Stripe columns already exist")


try:
    migrate_database()
except Exception as e:
    print(f"⚠️ Migration skipped: {e}")


# ============================================================================
# CONFIGURATION
# ============================================================================

MAX_FILES_PER_UPLOAD = 50
MAX_FILE_SIZE_MB = 25
MAX_TOTAL_SIZE_MB = 200
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}

limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


class APILoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import time

        start_time = time.time()

        response = await call_next(request)

        # Calculate response time
        response_time_ms = int((time.time() - start_time) * 1000)

        # Skip logging for health checks and static files
        if request.url.path not in ["/health", "/", "/docs", "/openapi.json"]:
            try:
                db = SessionLocal()
                log = APILog(
                    endpoint=request.url.path,
                    method=request.method,
                    status_code=response.status_code,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent", "")[:500],
                    response_time_ms=response_time_ms,
                )
                db.add(log)
                db.commit()
                db.close()
            except Exception as e:
                print(f"API logging error: {e}")

        return response


# ============================================================================
# APP CONFIGURATION
# ============================================================================

app = FastAPI(
    title="Flo Permit",
    description="AI-powered permit analysis for South Florida",
    version="1.4.0",
    docs_url="/docs",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS - Allow all Vercel deployments
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "https://flopermit.vercel.app",
    "https://permit-pro-ai.vercel.app",
    "https://permitpro-ai.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(APILoggingMiddleware)

analysis_results = {}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def get_api_key() -> Optional[str]:
    return os.getenv("ANTHROPIC_API_KEY") or os.getenv("AI_PERMIT_KEY")


def sanitize_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    sanitized = re.sub(r"[^\w\-.]", "_", filename)
    sanitized = re.sub(r"\.{2,}", ".", sanitized)
    return sanitized[:255] if len(sanitized) > 255 else sanitized


def validate_file_type(filename: str) -> tuple:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not supported"
    return True, ext


def validate_mime_type(file_path: str) -> tuple:
    ext = os.path.splitext(file_path)[1].lower()
    ext_to_mime = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
    }
    return (
        (True, ext_to_mime[ext]) if ext in ext_to_mime else (False, f"Invalid: {ext}")
    )


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    return f"{size_bytes / (1024 * 1024):.1f}MB"


def send_password_reset_email(email: str, reset_token: str) -> bool:
    """Send password reset email via Resend"""
    try:
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"

        params = {
            "from": "Flo Permit <noreply@flopermit.com>",
            "to": [email],
            "subject": "Reset Your Flo Permit Password",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #06b6d4, #10b981); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">Flo Permit</h1>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <h2 style="color: #111827;">Reset Your Password</h2>
                    <p style="color: #4b5563; font-size: 16px;">
                        We received a request to reset your password. Click the button below to create a new password:
                    </p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{reset_link}" style="background: linear-gradient(135deg, #06b6d4, #10b981); color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    <p style="color: #6b7280; font-size: 14px;">
                        This link will expire in 30 minutes. If you didn't request a password reset, you can safely ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                    <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                        © 2025 Flo Permit - South Florida Permit Analysis
                    </p>
                </div>
            </div>
            """,
        }

        resend.Emails.send(params)
        return True
    except Exception as e:
        print(f"❌ Failed to send reset email: {str(e)}")
        return False


def send_welcome_email(email: str, full_name: str = None) -> bool:
    """Send welcome email to new users"""
    try:
        name = full_name or "there"

        params = {
            "from": "Flo Permit <noreply@flopermit.com>",
            "to": [email],
            "subject": "Welcome to Flo Permit! 🎉",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #06b6d4, #10b981); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">Welcome to Flo Permit!</h1>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <h2 style="color: #111827;">Hey {name}! 👋</h2>
                    <p style="color: #4b5563; font-size: 16px;">
                        Thanks for signing up for Flo Permit — your AI-powered permit analysis tool for South Florida.
                    </p>
                    <h3 style="color: #111827;">Here's what you can do:</h3>
                    <ul style="color: #4b5563; font-size: 16px; line-height: 1.8;">
                        <li>📄 Upload your permit documents (PDFs, images)</li>
                        <li>🤖 Get instant AI analysis of your permit package</li>
                        <li>✅ See what documents you have</li>
                        <li>❌ Find out what's missing</li>
                        <li>💡 Get recommendations to improve your submission</li>
                    </ul>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{FRONTEND_URL}" style="background: linear-gradient(135deg, #06b6d4, #10b981); color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                            Start Your First Analysis
                        </a>
                    </div>
                    <p style="color: #6b7280; font-size: 14px;">
                        Questions? Reply to this email or contact us at <a href="mailto:support@flopermit.com" style="color: #06b6d4;">support@flopermit.com</a>
                    </p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                    <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                        © 2025 Flo Permit - South Florida Permit Analysis
                    </p>
                </div>
            </div>
            """,
        }

        resend.Emails.send(params)
        return True
    except Exception as e:
        print(f"❌ Failed to send welcome email: {str(e)}")
        return False


def send_contact_email(name: str, email: str, subject: str, message: str) -> bool:
    """Send contact form submission to support"""
    try:
        params = {
            "from": "Flo Permit <noreply@flopermit.com>",
            "to": ["support@flopermit.com"],
            "reply_to": email,
            "subject": f"[Contact Form] {subject}",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #06b6d4, #10b981); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">New Contact Form Submission</h1>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <p style="color: #4b5563; font-size: 16px;"><strong>From:</strong> {name}</p>
                    <p style="color: #4b5563; font-size: 16px;"><strong>Email:</strong> {email}</p>
                    <p style="color: #4b5563; font-size: 16px;"><strong>Subject:</strong> {subject}</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #4b5563; font-size: 16px;"><strong>Message:</strong></p>
                    <p style="color: #4b5563; font-size: 16px; white-space: pre-wrap;">{message}</p>
                </div>
            </div>
            """,
        }

        resend.Emails.send(params)
        return True
    except Exception as e:
        print(f"❌ Failed to send contact email: {str(e)}")
        return False


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================


@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    try:
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        if len(user_data.password) < 8:
            raise HTTPException(
                status_code=400, detail="Password must be at least 8 characters"
            )

        new_user = User(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            full_name=user_data.full_name,
            company_name=user_data.company_name,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Send welcome email
        send_welcome_email(new_user.email, new_user.full_name)

        access_token = create_access_token(new_user.id, new_user.email)

        return TokenResponse(
            access_token=access_token,
            user=UserResponse(
                id=new_user.id,
                email=new_user.email,
                full_name=new_user.full_name,
                company_name=new_user.company_name,
                subscription_tier=new_user.subscription_tier,
                created_at=new_user.created_at,
            ),
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        print(traceback.format_exc())
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login and get access token"""
    try:
        user = db.query(User).filter(User.email == user_data.email).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=401, detail="Account is disabled")

        access_token = create_access_token(user.id, user.email)

        return TokenResponse(
            access_token=access_token,
            user=UserResponse(
                id=user.id,
                email=user.email,
                full_name=user.full_name,
                company_name=user.company_name,
                subscription_tier=user.subscription_tier,
                created_at=user.created_at,
            ),
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user(
    user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)
):
    """Get current user info"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        company_name=user.company_name,
        subscription_tier=user.subscription_tier,
        created_at=user.created_at,
    )


# ============================================================================
# PASSWORD RESET ENDPOINTS
# ============================================================================


@app.post("/api/auth/forgot-password")
async def forgot_password(
    request_data: ForgotPasswordRequest, db: Session = Depends(get_db)
):
    """Request a password reset email"""
    try:
        # Always return success to prevent email enumeration
        user = db.query(User).filter(User.email == request_data.email).first()

        if user:
            # Invalidate any existing reset tokens for this user
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == user.id, PasswordResetToken.used == False
            ).update({"used": True})

            # Generate new token
            token = generate_reset_token()
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=get_reset_token_expiry(),
            )
            db.add(reset_token)
            db.commit()

            # Send email
            send_password_reset_email(user.email, token)

        # Always return success (security: don't reveal if email exists)
        return {
            "success": True,
            "message": "If an account exists with this email, you will receive a password reset link.",
        }
    except Exception as e:
        print(f"❌ Forgot password error: {str(e)}")
        print(traceback.format_exc())
        # Still return success for security
        return {
            "success": True,
            "message": "If an account exists with this email, you will receive a password reset link.",
        }


@app.post("/api/auth/reset-password")
async def reset_password(
    request_data: ResetPasswordRequest, db: Session = Depends(get_db)
):
    """Reset password using token"""
    try:
        # Find the token
        reset_token = (
            db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.token == request_data.token,
                PasswordResetToken.used == False,
            )
            .first()
        )

        if not reset_token:
            raise HTTPException(status_code=400, detail="Invalid or expired reset link")

        if is_token_expired(reset_token.expires_at):
            reset_token.used = True
            db.commit()
            raise HTTPException(
                status_code=400,
                detail="Reset link has expired. Please request a new one.",
            )

        # Validate new password
        if len(request_data.new_password) < 8:
            raise HTTPException(
                status_code=400, detail="Password must be at least 8 characters"
            )

        # Update password
        user = db.query(User).filter(User.id == reset_token.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.hashed_password = hash_password(request_data.new_password)
        user.updated_at = datetime.utcnow()

        # Mark token as used
        reset_token.used = True

        db.commit()

        return {
            "success": True,
            "message": "Password has been reset successfully. You can now log in with your new password.",
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Reset password error: {str(e)}")
        print(traceback.format_exc())
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Password reset failed: {str(e)}")


# ============================================================================
# PROFILE ENDPOINTS
# ============================================================================


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    company_name: Optional[str] = None
    phone: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@app.get("/api/profile")
async def get_profile(
    user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)
):
    """Get full user profile with stats"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    total_analyses = (
        db.query(AnalysisHistory).filter(AnalysisHistory.user_id == user_id).count()
    )

    first_of_month = datetime.utcnow().replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    analyses_this_month = (
        db.query(AnalysisHistory)
        .filter(
            AnalysisHistory.user_id == user_id,
            AnalysisHistory.created_at >= first_of_month,
        )
        .count()
    )

    recent_analyses = (
        db.query(AnalysisHistory)
        .filter(AnalysisHistory.user_id == user_id)
        .order_by(AnalysisHistory.created_at.desc())
        .limit(5)
        .all()
    )

    limits = {
        "free": {"analyses_per_month": 3},
        "pro": {"analyses_per_month": -1},
        "business": {"analyses_per_month": -1},
    }
    tier_limits = limits.get(user.subscription_tier, limits["free"])

    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "company_name": user.company_name,
            "phone": getattr(user, "phone", None),
            "created_at": user.created_at.isoformat(),
        },
        "subscription": {
            "tier": user.subscription_tier,
            "limits": tier_limits,
            "analyses_this_month": analyses_this_month,
            "analyses_remaining": tier_limits["analyses_per_month"]
            - analyses_this_month
            if tier_limits["analyses_per_month"] > 0
            else -1,
        },
        "stats": {
            "total_analyses": total_analyses,
            "analyses_this_month": analyses_this_month,
        },
        "recent_analyses": [
            {
                "id": a.id,
                "analysis_uuid": a.analysis_uuid,
                "city": a.city,
                "permit_type": a.permit_type,
                "compliance_score": a.compliance_score,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_analyses
        ],
    }


@app.put("/api/profile")
async def update_profile(
    profile_data: ProfileUpdate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Update user profile"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if profile_data.full_name is not None:
        user.full_name = profile_data.full_name
    if profile_data.company_name is not None:
        user.company_name = profile_data.company_name
    if profile_data.phone is not None:
        user.phone = profile_data.phone

    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)

    return {"success": True, "message": "Profile updated"}


@app.post("/api/profile/change-password")
async def change_password(
    password_data: PasswordChange,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Change user password"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=400, detail="New password must be at least 8 characters"
        )

    user.hashed_password = hash_password(password_data.new_password)
    user.updated_at = datetime.utcnow()
    db.commit()

    return {"success": True, "message": "Password changed successfully"}


# ============================================================================
# ANALYSIS HISTORY ENDPOINTS
# ============================================================================


@app.get("/api/history")
async def get_analysis_history(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    limit: int = 20,
    offset: int = 0,
    search: Optional[str] = None,
):
    """Get user's analysis history"""
    query = db.query(AnalysisHistory).filter(AnalysisHistory.user_id == user_id)

    if search:
        query = query.filter(
            (AnalysisHistory.city.ilike(f"%{search}%"))
            | (AnalysisHistory.permit_type.ilike(f"%{search}%"))
        )

    total = query.count()
    analyses = (
        query.order_by(AnalysisHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "analyses": [
            {
                "id": a.id,
                "analysis_uuid": a.analysis_uuid,
                "city": a.city,
                "permit_type": a.permit_type,
                "files_analyzed": a.files_analyzed,
                "overall_status": a.overall_status,
                "compliance_score": a.compliance_score,
                "created_at": a.created_at.isoformat(),
            }
            for a in analyses
        ],
        "total": total,
    }


@app.get("/api/history/{analysis_uuid}")
async def get_analysis_detail(
    analysis_uuid: str,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Get detailed analysis"""
    analysis = (
        db.query(AnalysisHistory)
        .filter(
            AnalysisHistory.analysis_uuid == analysis_uuid,
            AnalysisHistory.user_id == user_id,
        )
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "id": analysis.id,
        "analysis_uuid": analysis.analysis_uuid,
        "city": analysis.city,
        "permit_type": analysis.permit_type,
        "files_analyzed": analysis.files_analyzed,
        "file_list": json.loads(analysis.file_list) if analysis.file_list else [],
        "compliance_score": analysis.compliance_score,
        "analysis": json.loads(analysis.analysis_data)
        if analysis.analysis_data
        else {},
        "created_at": analysis.created_at.isoformat(),
    }


@app.delete("/api/history/{analysis_uuid}")
async def delete_analysis(
    analysis_uuid: str,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Delete analysis"""
    analysis = (
        db.query(AnalysisHistory)
        .filter(
            AnalysisHistory.analysis_uuid == analysis_uuid,
            AnalysisHistory.user_id == user_id,
        )
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    db.delete(analysis)
    db.commit()
    return {"success": True}


def save_analysis_to_history(
    db,
    user_id,
    analysis_uuid,
    city,
    permit_type,
    files_analyzed,
    file_list,
    total_size_bytes,
    analysis_data,
):
    """Save analysis to history"""
    history = AnalysisHistory(
        analysis_uuid=analysis_uuid,
        user_id=user_id,
        city=city,
        permit_type=permit_type,
        files_analyzed=files_analyzed,
        file_list=json.dumps(file_list),
        total_size_bytes=total_size_bytes,
        overall_status=analysis_data.get("overall_status"),
        compliance_score=analysis_data.get("compliance_score"),
        analysis_data=json.dumps(analysis_data),
    )
    db.add(history)
    db.commit()


# ============================================================================
# HEALTH ENDPOINTS
# ============================================================================


@app.get("/")
async def root():
    return {"service": "Flo Permit", "version": "1.6.0", "status": "running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ============================================================================
# ADMIN DASHBOARD
# ============================================================================

ADMIN_EMAILS = ["toshygluestick@gmail.com"]


def require_admin(user_id: int, db: Session):
    """Check if user is an admin"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.email not in ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.get("/api/admin/stats")
async def get_admin_stats(
    authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Get admin dashboard statistics"""
    user_id = get_current_user_id(authorization)
    require_admin(user_id, db)

    from sqlalchemy import func

    # Total users
    total_users = db.query(User).count()

    # Users this month
    first_of_month = datetime.utcnow().replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    new_users_this_month = (
        db.query(User).filter(User.created_at >= first_of_month).count()
    )

    # Total analyses
    total_analyses = db.query(AnalysisHistory).count()

    # Analyses this month
    analyses_this_month = (
        db.query(AnalysisHistory)
        .filter(AnalysisHistory.created_at >= first_of_month)
        .count()
    )

    # Average compliance score
    avg_score = db.query(func.avg(AnalysisHistory.compliance_score)).scalar() or 0

    # API requests today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    api_requests_today = (
        db.query(APILog).filter(APILog.created_at >= today_start).count()
    )

    # API requests this month
    api_requests_month = (
        db.query(APILog).filter(APILog.created_at >= first_of_month).count()
    )

    # Most popular cities
    popular_cities = (
        db.query(AnalysisHistory.city, func.count(AnalysisHistory.id).label("count"))
        .group_by(AnalysisHistory.city)
        .order_by(func.count(AnalysisHistory.id).desc())
        .limit(5)
        .all()
    )

    # Most popular permit types
    popular_permits = (
        db.query(
            AnalysisHistory.permit_type, func.count(AnalysisHistory.id).label("count")
        )
        .group_by(AnalysisHistory.permit_type)
        .order_by(func.count(AnalysisHistory.id).desc())
        .limit(5)
        .all()
    )

    # Recent users
    recent_users = db.query(User).order_by(User.created_at.desc()).limit(10).all()

    # Recent analyses
    recent_analyses = (
        db.query(AnalysisHistory)
        .order_by(AnalysisHistory.created_at.desc())
        .limit(10)
        .all()
    )

    # API endpoint stats
    endpoint_stats = (
        db.query(
            APILog.endpoint,
            func.count(APILog.id).label("count"),
            func.avg(APILog.response_time_ms).label("avg_time"),
        )
        .filter(APILog.created_at >= first_of_month)
        .group_by(APILog.endpoint)
        .order_by(func.count(APILog.id).desc())
        .limit(10)
        .all()
    )

    return {
        "overview": {
            "total_users": total_users,
            "new_users_this_month": new_users_this_month,
            "total_analyses": total_analyses,
            "analyses_this_month": analyses_this_month,
            "average_compliance_score": round(avg_score, 1),
            "api_requests_today": api_requests_today,
            "api_requests_this_month": api_requests_month,
        },
        "popular_cities": [{"city": c, "count": cnt} for c, cnt in popular_cities],
        "popular_permits": [
            {"permit_type": p, "count": cnt} for p, cnt in popular_permits
        ],
        "recent_users": [
            {
                "id": u.id,
                "email": u.email,
                "full_name": u.full_name,
                "company_name": u.company_name,
                "created_at": u.created_at.isoformat(),
            }
            for u in recent_users
        ],
        "recent_analyses": [
            {
                "id": a.id,
                "city": a.city,
                "permit_type": a.permit_type,
                "compliance_score": a.compliance_score,
                "files_analyzed": a.files_analyzed,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_analyses
        ],
        "endpoint_stats": [
            {"endpoint": e, "count": cnt, "avg_response_ms": round(avg or 0, 1)}
            for e, cnt, avg in endpoint_stats
        ],
    }


# ============================================================================
# CONTACT FORM
# ============================================================================


class ContactForm(BaseModel):
    name: str
    email: str
    subject: str
    message: str


@app.post("/api/contact")
async def submit_contact_form(form_data: ContactForm):
    """Handle contact form submission"""
    try:
        success = send_contact_email(
            name=form_data.name,
            email=form_data.email,
            subject=form_data.subject,
            message=form_data.message,
        )
        if success:
            return {
                "success": True,
                "message": "Message sent! We'll get back to you soon.",
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to send message")
    except Exception as e:
        print(f"❌ Contact form error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send message")


# ============================================================================
# STRIPE PAYMENTS
# ============================================================================


@app.get("/api/pricing")
async def get_pricing():
    """Get pricing tiers"""
    return {
        "tiers": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "period": "month",
                "analyses": 3,
                "features": ["3 analyses/month", "Basic AI analysis", "Email support"],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": 29,
                "period": "month",
                "analyses": 50,
                "features": [
                    "50 analyses/month",
                    "Priority AI analysis",
                    "Priority support",
                    "Analysis history",
                ],
                "popular": True,
            },
            {
                "id": "business",
                "name": "Business",
                "price": 99,
                "period": "month",
                "analyses": -1,
                "features": [
                    "Unlimited analyses",
                    "Priority AI analysis",
                    "Dedicated support",
                    "Analysis history",
                    "Team features (coming soon)",
                ],
            },
        ]
    }


@app.post("/api/stripe/create-checkout-session")
async def create_checkout_session(
    tier: str = Form(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Create Stripe checkout session for subscription"""
    try:
        # Parse token from authorization header
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")

        token = authorization[7:]  # Remove "Bearer " prefix
        payload = decode_access_token(token)
        user_id = int(payload.get("sub"))

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if tier not in STRIPE_PRICES:
            raise HTTPException(status_code=400, detail="Invalid tier")

        # Create or get Stripe customer
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                name=user.full_name,
                metadata={"user_id": str(user.id)},
            )
            user.stripe_customer_id = customer.id
            db.commit()

        # Create checkout session
        session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[
                {
                    "price": STRIPE_PRICES[tier],
                    "quantity": 1,
                }
            ],
            mode="subscription",
            success_url=f"{FRONTEND_URL}?payment=success&tier={tier}",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            metadata={
                "user_id": str(user.id),
                "tier": tier,
            },
        )

        return {"checkout_url": session.url, "session_id": session.id}

    except stripe.error.StripeError as e:
        print(f"❌ Stripe error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment error: {str(e)}")
    except Exception as e:
        print(f"❌ Checkout error: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Checkout error: {str(e)}")


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Handle Stripe webhooks"""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            event = json.loads(payload)
    except Exception as e:
        print(f"❌ Webhook error: {str(e)}")
        raise HTTPException(status_code=400, detail="Webhook error")

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        # Payment successful
        customer_id = data.get("customer")
        subscription_id = data.get("subscription")
        tier = data.get("metadata", {}).get("tier", "pro")

        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.subscription_tier = tier
            user.stripe_subscription_id = subscription_id
            db.commit()
            print(f"✅ User {user.email} upgraded to {tier}")

    elif event_type == "customer.subscription.deleted":
        # Subscription cancelled
        customer_id = data.get("customer")
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.subscription_tier = "free"
            user.stripe_subscription_id = None
            db.commit()
            print(f"✅ User {user.email} downgraded to free")

    elif event_type == "customer.subscription.updated":
        # Subscription updated
        customer_id = data.get("customer")
        status = data.get("status")
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user and status == "canceled":
            user.subscription_tier = "free"
            user.stripe_subscription_id = None
            db.commit()

    return {"status": "success"}


@app.post("/api/stripe/create-portal-session")
async def create_portal_session(
    authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Create Stripe billing portal session"""
    # Parse token from authorization header
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization[7:]  # Remove "Bearer " prefix
    payload = decode_access_token(token)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account found")

    try:
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=f"{FRONTEND_URL}?page=profile",
        )
        return {"portal_url": session.url}
    except stripe.error.StripeError as e:
        print(f"❌ Portal error: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not create portal session")


@app.get("/api/subscription")
async def get_subscription(
    authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Get user's subscription status"""
    try:
        # Parse token from authorization header
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")

        token = authorization[7:]  # Remove "Bearer " prefix
        payload = decode_access_token(token)
        user_id = int(payload.get("sub"))

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Count analyses this month
        first_of_month = datetime.utcnow().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        analyses_this_month = (
            db.query(AnalysisHistory)
            .filter(
                AnalysisHistory.user_id == user.id,
                AnalysisHistory.created_at >= first_of_month,
            )
            .count()
        )

        tier = user.subscription_tier or "free"
        tier_limit = TIER_LIMITS.get(tier, 3)

        return {
            "tier": tier,
            "analyses_this_month": analyses_this_month,
            "analyses_limit": tier_limit,
            "analyses_remaining": max(0, tier_limit - analyses_this_month)
            if tier_limit < 999999
            else -1,
            "has_subscription": bool(user.stripe_subscription_id),
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Subscription error: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Subscription error: {str(e)}")


@app.get("/api/cities")
async def get_cities():
    cities = {
        "Fort Lauderdale": {"key": "fort_lauderdale", "county": "Broward"},
        "Pompano Beach": {"key": "pompano_beach", "county": "Broward"},
        "Hollywood": {"key": "hollywood", "county": "Broward"},
        "Coral Springs": {"key": "coral_springs", "county": "Broward"},
        "Boca Raton": {"key": "boca_raton", "county": "Palm Beach"},
        "Lauderdale-by-the-Sea": {"key": "lauderdale_by_the_sea", "county": "Broward"},
        "Deerfield Beach": {"key": "deerfield_beach", "county": "Broward"},
        "Pembroke Pines": {"key": "pembroke_pines", "county": "Broward"},
        "Lighthouse Point": {"key": "lighthouse_point", "county": "Broward"},
        "Weston": {"key": "weston", "county": "Broward"},
        "Lake Worth": {"key": "lake_worth", "county": "Palm Beach"},
        "Davie": {"key": "davie", "county": "Broward"},
        "Plantation": {"key": "plantation", "county": "Broward"},
        "Sunrise": {"key": "sunrise", "county": "Broward"},
        "Miramar": {"key": "miramar", "county": "Broward"},
        "Delray Beach": {"key": "delray_beach", "county": "Palm Beach"},
        "Boynton Beach": {"key": "boynton_beach", "county": "Palm Beach"},
        "West Palm Beach": {"key": "west_palm_beach", "county": "Palm Beach"},
    }
    return {"cities": cities}


@app.get("/api/pricing")
async def get_pricing():
    return {
        "tiers": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "features": ["3 analyses/month", "Basic AI", "Email support"],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": 49,
                "features": [
                    "Unlimited analyses",
                    "Advanced AI",
                    "Priority support",
                    "History",
                ],
                "popular": True,
            },
            {
                "id": "business",
                "name": "Business",
                "price": 149,
                "features": ["Everything in Pro", "Team (5 users)", "API access"],
            },
        ]
    }


# ============================================================================
# MULTI-FILE ANALYSIS
# ============================================================================


@app.post("/api/analyze-permit-folder")
@limiter.limit("10/minute;100/hour")
async def analyze_permit_folder(
    request: Request,
    files: List[UploadFile] = File(...),
    city: str = Form(...),
    permit_type: str = Form(...),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Analyze permit folder"""
    user_id = None
    user = None
    if authorization and authorization.startswith("Bearer "):
        try:
            from auth import decode_access_token

            payload = decode_access_token(authorization[7:])
            user_id = int(payload.get("sub"))
            user = db.query(User).filter(User.id == user_id).first()
        except:
            pass

    # Check usage limits for authenticated users
    if user:
        first_of_month = datetime.utcnow().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        analyses_this_month = (
            db.query(AnalysisHistory)
            .filter(
                AnalysisHistory.user_id == user.id,
                AnalysisHistory.created_at >= first_of_month,
            )
            .count()
        )

        tier_limit = TIER_LIMITS.get(user.subscription_tier, 3)
        if analyses_this_month >= tier_limit:
            raise HTTPException(
                status_code=403,
                detail=f"Monthly limit reached ({tier_limit} analyses). Please upgrade your plan.",
            )

    if len(files) > MAX_FILES_PER_UPLOAD:
        raise HTTPException(status_code=400, detail=f"Max {MAX_FILES_PER_UPLOAD} files")
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    api_key = get_api_key()
    if not api_key:
        raise HTTPException(status_code=500, detail="API key not configured")

    analysis_id = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp()

    try:
        processed_files = []
        total_size = 0
        all_text = []

        for f in files:
            is_valid, ext = validate_file_type(f.filename)
            if not is_valid:
                continue

            safe_name = sanitize_filename(f.filename)
            path = os.path.join(temp_dir, f"{len(processed_files)}_{safe_name}")

            with open(path, "wb") as buf:
                shutil.copyfileobj(f.file, buf)

            size = os.path.getsize(path)
            if size > MAX_FILE_SIZE_MB * 1024 * 1024:
                os.remove(path)
                continue

            total_size += size
            processed_files.append(
                {"name": f.filename, "path": path, "size": format_file_size(size)}
            )

        if not processed_files:
            raise HTTPException(status_code=400, detail="No valid files")

        for pf in processed_files:
            try:
                text = get_document_text(pf["path"], is_blueprint=False)
                all_text.append(
                    f"\n=== {pf['name']} ===\n{text if text else '[No text]'}"
                )
            except:
                all_text.append(f"\n=== {pf['name']} ===\n[Error reading]")

        city_key = get_city_key(city)
        requirements = get_permit_requirements(city_key, permit_type)
        if not requirements:
            raise HTTPException(
                status_code=404, detail=f"No requirements for {city} - {permit_type}"
            )

        analysis = analyze_folder_with_claude(
            "\n".join(all_text), requirements, api_key, len(processed_files)
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        if user_id:
            try:
                save_analysis_to_history(
                    db,
                    user_id,
                    analysis_id,
                    city,
                    requirements["name"],
                    len(processed_files),
                    file_tree,
                    total_size,
                    analysis,
                )
            except Exception as e:
                print(f"Failed to save history: {e}")

        shutil.rmtree(temp_dir)

        return {
            "success": True,
            "analysis_id": analysis_id,
            "files_analyzed": len(processed_files),
            "file_tree": file_tree,
            "analysis": analysis,
            "city": city,
            "permit_type": requirements["name"],
        }

    except HTTPException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


def analyze_folder_with_claude(
    text: str, requirements: dict, api_key: str, file_count: int
) -> dict:
    """Analyze with Claude - Enhanced version with city-specific knowledge"""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    reqs = "\n".join([f"- {item}" for item in requirements.get("items", [])])
    permit_name = requirements.get("name", "permit")
    city_name = requirements.get("city", "South Florida")
    city_key = requirements.get("city_key", "")
    gotchas = requirements.get("gotchas", [])
    tips = requirements.get("tips", [])
    city_info = requirements.get("city_info", {})

    if len(text) > 200000:
        text = text[:200000] + "\n[truncated]"

    # Build city-specific context
    city_context = ""
    if city_key == "fort_lauderdale":
        city_context = """
FORT LAUDERDALE SPECIFIC REQUIREMENTS:
- Portal: LauderBuild (100% digital - NO paper applications accepted)
- Plan sets: 2 required
- Insurance holder MUST read exactly: "City of Fort Lauderdale, 700 NW 19th Avenue, Fort Lauderdale, FL 33311"
- 50% of permit fee due at application
- NOC threshold: $2,500 (roofing: $5,000)
- Product approvals must be CIRCLED (not highlighted) on NOA documents
- Hurricane mitigation affidavit required for re-roofs on homes assessed ≥$300,000
- EPD approval must be obtained BEFORE city submittal
- Permits expire 180 days without inspection

FORT LAUDERDALE MARINE REQUIREMENTS:
- Minimum seawall elevation: 3.9 feet NAVD88
- Dock extension limit: 30% of waterway width
- Side setback: 5 feet from extended property line
- Reflector tape required on piles extending beyond limits
- Substantial repair (>50% seawall length) = full code compliance required
"""
    elif city_key == "pompano_beach":
        city_context = """
POMPANO BEACH SPECIFIC REQUIREMENTS:
- Portal: Click2Gov
- Applications MUST be in BLACK INK - will be rejected otherwise!
- Plan sets: Only 1 required (100% electronic review)
- Fire Review Application REQUIRED for ALL permits (Pompano-specific)
- Both owner AND contractor signatures required, notarized
- NOC thresholds vary: General >$2,500, HVAC >$5,000, Roofing >$7,500
- New/relocated electrical service must be UNDERGROUND (City Ordinance 152.07)
- Emergency A/C repairs: Must notify Chief Mechanical Inspector BEFORE starting
- EPD must be approved BEFORE city submittal
- Work without permit = DOUBLE the permit fee

POMPANO BEACH MARINE REQUIREMENTS:
- Dock extension: 10% of waterway width OR 8 feet (whichever is less)
- Boat lift: 20% of waterway width OR 20 feet (whichever is less)
- Engineering permit fee: 4% of construction cost (min $100)
"""
    elif city_key == "lauderdale_by_the_sea":
        city_context = """
LAUDERDALE-BY-THE-SEA SPECIFIC REQUIREMENTS:
- Portal: CitizenServe
- Notice of Commencement must be RECORDED before submittal - #1 rejection reason!
- Plan sets: 2 required (PDF, landscape oriented, electronically signed/sealed)
- Insurance must list exactly: "Town of Lauderdale by the Sea"
- Trade applications must be in BLACK INK
- Contract must show itemized price breakdown for all trades
- Fee structure: New construction 2%, Renovations 3%, Roofing 1.5%, Pools 5%
- EPD approval required for: new construction, additions, alterations to non-residential, demolitions, generators
- 50%+ renovation triggers EPD approval and may require flood zone compliance upgrades
- Demolition permits expire in 60 days (shorter than other permits)
- Work without permit = DOUBLE the permit fee
"""
    elif city_key == "lighthouse_point":
        city_context = """
LIGHTHOUSE POINT SPECIFIC REQUIREMENTS:
- Portal: SmartGov
- NO FAXED applications - will be rejected (distorts information)
- Survey must be less than 1 year old OR submit Zoning Affidavit
- Applications must be signed by BOTH owner AND contractor
- Many applications require notarization
- Values, SF, and quantities MUST be included on all applications
- Permits must be picked up IN PERSON
- Be home for inspections (except final zoning, final exterior, final fire)
- Buildings over 25 years AND over 3,500 SF require 40-year safety inspection
- Work without permit = 200% of standard fee (tripled!)
- Application fees: New construction $1,000, Remodel $200

LIGHTHOUSE POINT - NO OWNER/BUILDER ALLOWED FOR:
- ALL electrical work
- ALL roofing work  
- ALL piling work
Licensed contractors REQUIRED for these trades!

LIGHTHOUSE POINT MARINE - CRITICAL:
- Longshoreman Insurance REQUIRED (FEDERAL requirement)
- State Workers' Compensation does NOT satisfy federal requirement
- Waterfront properties require 2 signed/sealed engineer letters regarding seawall condition
- Must provide updated dock/seawall survey before final inspection
"""
    elif city_key == "weston":
        city_context = """
WESTON SPECIFIC REQUIREMENTS:
- Portal: Accela ePermits
- FILE NAMING = AUTOMATIC DENIAL - Download 'Weston Electronic File Naming Conventions' FIRST
- Digital signatures must follow City's specific Digital Sign and Seal Requirements
- ORIGINAL SIGNATURES ONLY - copies NOT acceptable
- Permit Acknowledgement Affidavit requires original notarized signature (residential)
- Survey must be less than 1 YEAR old (FL Professional Surveyor with raised seal - 2 originals)
- Broward County EPD approval required BEFORE Building Department submittal
- Original DRC approved plans must be submitted (stamped/signed)
- SEPARATE CHECKS REQUIRED for each trade permit - CASH NOT ACCEPTED
- Work without permit = DOUBLE the permit fee
- ISO Rating: Class 2 (High Standards)
- Free virtual training available: Tues 11AM, Thurs 2PM

WESTON HVHZ REQUIREMENTS:
- Design wind speed: 175 mph
- All exterior products require Miami-Dade NOA or FL Product Approval (HVHZ designation)
- NOAs must be stamped by architect for windows, doors, louvers, shutters
- Roof calculations must include complete package with NOAs and roof plan

WESTON POOL PERMITS:
- Pool Safety Affirmation required
- Residential Pool Safety Act Form required
- Barrier requirements: 48" min height, self-closing/latching gates
- FL DOH Application required for commercial pools BEFORE building permit
"""
    elif city_key == "davie":
        city_context = """
DAVIE SPECIFIC REQUIREMENTS:
- Portal: OAS (Online Application Submittal) - Starting Jan 12, 2026
- Applications must be IN INK - ALL fields must be completed
- BCPA Property Search printout from www.bcpa.net is ALWAYS REQUIRED
- Survey must be less than 2 YEARS old (longer than most cities!)
- Survey must show ALL easements and encumbrances - do NOT reduce size
- Survey Affidavit required if using older survey
- NEW Broward County form required as of 12/22/2025

DAVIE NOC REQUIREMENTS - CRITICAL:
- NOC MUST BE POSTED AT JOB SITE for first inspection
- Without posted NOC: inspection NOT approved + re-inspection fee charged
- NOC threshold: General $2,500, HVAC $7,500, Fence $5,000

DAVIE WALK-THROUGH PERMITS:
- Wednesdays 8AM-10:30AM ONLY (2 apps max per customer)
- Single discipline only, paper packages with clips (no staples)
- Available for: Re-roofs (residential), Garage Doors, Shutters, Windows/Doors, Service Change

DAVIE INSPECTION RULES:
- Cannot cancel inspections after 8:30 AM - late cancellation = fees
- After 3rd failed re-inspection: QUALIFIER MUST BE PRESENT ($150 fee)
- Roofing: Have OSHA-approved ladder set up and secured to roof on inspection day

DAVIE MARINE - UNIQUE REQUIREMENT:
- ALL DOCKS MUST HAVE HIP STYLE ROOF (Davie-specific!)

DAVIE PRIVATE PROVIDER DISCOUNTS:
- Plan Review Only: 20% discount
- Inspection Only: 20% discount
- Both Plan Review AND Inspection: 40% discount

DAVIE OWNER-BUILDER:
- Owner must bring application IN PERSON
"""
    elif city_key == "coral_springs":
        city_context = """
CORAL SPRINGS SPECIFIC REQUIREMENTS:
- Portal: eTrakit (etrakit.coralsprings.gov)
- Electronic submittals: 7 business days review
- Hard copy submittals: 15 business days review
- Once you choose format, ALL subsequent submittals must remain same format
- Submit 3 sets of plans (city recommends)
- NEW Broward County form required as of December 1, 2025
- Deposits: $100 (SFR), $200 (all other)

CORAL SPRINGS INSPECTION RULES:
- Phone scheduling NO LONGER AVAILABLE (Feb 2025) - use eTrakit ONLY
- Cancel before 8:00 AM day of inspection or face re-inspection fee
- Truss drawings must be received BEFORE foundation inspection
- Bearing capacity certification must be approved BEFORE foundation inspection
- Fire Dept re-inspection fee ($235.72) MUCH higher than Building ($85.11)

CORAL SPRINGS PLAN REVIEW REQUIREMENTS:
- Plans must be sealed and dated - EACH sheet sealed for jobs >$15,000
- Product approvals must be reviewed by designer of record BEFORE submission
- Shop drawings must be reviewed by designer BEFORE submission to city
- Missing ADA disproportionate cost documentation = rejection

CORAL SPRINGS SPECIAL REQUIREMENTS:
- Window restrictors required on ALL second-story bedroom windows
- Roof color must be on approved list - get Zoning approval BEFORE permit
- DRC approval must be completed BEFORE Zoning approval
- Public Art Ordinance applies to commercial projects

CORAL SPRINGS PRIVATE PROVIDER:
- 30% discount for plan review + inspection
- 15% discount for inspection only
"""
    elif city_key == "coconut_creek":
        city_context = """
COCONUT CREEK SPECIFIC REQUIREMENTS:
- Portal: ePermits
- Building Department is CLOSED ON FRIDAYS
- Applications must be in BLACK INK
- Hours: Monday-Thursday 7:00 AM - 6:00 PM only

COCONUT CREEK SUBMISSION RULES:
- PDF Portfolio uploads NOT compatible - must be regular unlocked PDF files
- NOC must be recorded at County BEFORE submitting to Building Dept
- Both owner AND contractor signatures required on application
- Contractor must be registered with city
- Values, SF, and quantities MUST be included on application

COCONUT CREEK FEES:
- Premium Service Fee: $107/hour for enhanced plan review
- Minimum Base Permit Fee: $125
- Structural Permit Fee: 1.85% of job value

COCONUT CREEK MECHANICAL:
- Email ebuilding@coconutcreek.gov for Mechanical Contractor Verification Letter
"""
    elif city_key == "boca_raton":
        city_context = """
BOCA RATON SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Portal: Boca eHub (bocaehub.com)
- DO NOT USE C2GOV for new applications - will be REJECTED
- Use Boca ePlans/ProjectDox for plan review uploads
- NOT in HVHZ (Palm Beach County)

BOCA RATON PENALTIES - SEVERE:
- Work without permit = TRIPLE the standard fee
- Work before Development Order = TRIPLE the standard fee

BOCA RATON OWNER/BUILDER RESTRICTIONS:
- Property must be single-family home
- You must be listed as owner
- Property cannot be owned by a business
- Must currently be living there (not renting it out)

BOCA RATON COMMERCIAL:
- CGL insurance: $1,000,000 each occurrence minimum
- $2,000,000 general aggregate minimum
- Community Appearance Board (CAB) approval required

BOCA RATON MARINE CONSTRUCTION:
- Outside agency approvals (DEP, County ERM, ACOE) required BEFORE city
- Dock limits: <100ft waterway = 6ft max, ≥100ft = 8ft max projection
- Dock setback from adjacent property: minimum 10 feet
- Each dock requires ladder extending 2ft below mean low water

BOCA RATON FEES:
- TCO fees escalate: 1st extension $3-8K, 2nd $5-15K, 3rd $10-25K
- HOA Affidavit required for HOA properties
- NOAs must be stamped by architect verifying wind zone
"""
    elif city_key == "lake_worth_beach":
        city_context = """
LAKE WORTH BEACH SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Walk-In Hours: 1st & 3rd Wednesdays 8AM-12PM only (no appointment)
- Inspection requests must be made by 4:00 PM day before
- NOT in HVHZ (Palm Beach County)

LAKE WORTH BEACH PENALTIES:
- Work without permit = Permit fee PLUS 3x fee (without surcharges)
- Third plan review = $50 fee
- Fourth+ plan review = 4x Plan Filing Fee

LAKE WORTH BEACH HISTORIC DISTRICT - CRITICAL:
- Properties in historic districts require Certificate of Appropriateness BEFORE permit
- Full demolition fee: $500 (primary structure), $250 (accessory)
- Certificate of Appropriateness adds time - start early

LAKE WORTH BEACH SUBMISSION:
- Contractor must be registered with city
- NOC must be recorded with Clerk of Court AND posted on job site
- Plan Filing Fee (50% of permit) is non-refundable

LAKE WORTH BEACH EXEMPTIONS:
- Permits under $1,000 for minor repairs may be exempt
- Check exemption list before applying
"""
    elif city_key == "margate":
        city_context = """
MARGATE SPECIFIC REQUIREMENTS:
- Portal: ProjectDox
- Applications must be in BLACK INK
- Applications must be signed by BOTH Owner AND Contractor
- Signatures must be NOTARIZED
- Fill in address on second page (mandatory field - causes rejections!)

MARGATE INSPECTION SCHEDULE:
- Building inspectors work Monday-Thursday ONLY
- Building Department CLOSED Fridays for inspections
- Call before 2:00 PM for next-business-day inspection

MARGATE UNIQUE REQUIREMENTS:
- Energy calculations: THREE SETS required (Margate-specific)
- Proof of ownership required (beyond standard Broward requirements)
- HOA approval required FIRST - city permit does NOT guarantee HOA approval
- NOC threshold for AC: $7,500 (higher than standard $2,500)

MARGATE ROOFING - CRITICAL:
- AC stands for re-roofs: New energy code requires larger units - CONTACT CITY FIRST
- Roofing inspections: Photos NOT accepted - must be in-person inspection
- Tile calculations must use Method 1, 2, or 3 per RAS 127

MARGATE MARINE:
- Multi-agency approval (DPEP, Army Corps, DNR) required BEFORE city submission
- Special Structural Inspector required per FBC 110.10.1.1

MARGATE PENALTIES:
- Work without permit = $200 or DOUBLE permit fee (whichever greater)
- Continuing work after Stop Work Order = $500 penalty
"""
    elif city_key == "tamarac":
        city_context = """
TAMARAC SPECIFIC REQUIREMENTS:
- Portal: ePermits (Click2Gov)
- 100% PAPERLESS department since March 2014 - ALL electronic
- Contractor must be REGISTERED with city (no fee to register)
- IVR System for inspections/status - requires PIN

TAMARAC SUBMISSION RULES:
- Paper plans (up to 3 large pages) converted for additional fee
- Plans with 3+ pages MUST be submitted online or flash drive/CD
- NOC must be recorded BEFORE Building Dept submission
- As of November 14, 2025: New Broward County form required
- Notary Jurat form NO LONGER needed with new form version

TAMARAC ROOFING - CRITICAL:
- AC Stands: CONTACT BUILDING DEPT BEFORE submitting re-roof - especially condos
- New Florida Building Energy Code requires larger AC units
- Roofing inspections: Photos NOT accepted (FBC 1512.4.2) - in-person only
- Renailing wood decks may be required per Chapter 16 (HVHZ)

TAMARAC HVAC:
- Smoke detector may be required with package unit ($122 extra)

TAMARAC REVIEW TIMES:
- 5-10 business days for minor projects
- Up to 30 days for larger projects
- Predevelopment meetings available - recommended for complex projects

TAMARAC NOA NOTE:
- For replacement permits (windows, doors, re-roof) NOAs don't need architect review

TAMARAC PENALTIES:
- Work without permit: $285 or DOUBLE (contractors), $190 or DOUBLE (homeowners)

TAMARAC PRIVATE PROVIDER:
- 5% discount for inspections only
- 10% discount for plan review + inspections
"""
    elif city_key == "deerfield_beach":
        city_context = """
DEERFIELD BEACH SPECIFIC REQUIREMENTS:
- Portal: ePermitsOneStop (Building services by CAP Government as of Dec 15, 2025)
- Applications must be in BLACK INK
- HOA Affidavit REQUIRED for ALL residential permits - #1 rejection reason!
- Both owner AND trade contractor must sign application
- Values, SF & quantities must be included

DEERFIELD BEACH ASBESTOS - CRITICAL:
- ASBESTOS STATEMENT IS MANDATORY for ALL re-roofs - no exceptions
- Submit through Broward County

DEERFIELD BEACH PRE-SUBMITTAL:
- EPD approval required BEFORE Building Dept submittal
- Elevator approval required BEFORE Building Dept (allow 1 week)
- NOC must be recorded BEFORE permit submission (if over $2,500)

DEERFIELD BEACH SPECIAL RULES:
- Condo owners CANNOT do work themselves - must hire licensed contractor
- Violation is a FELONY under Florida Statute 489.127(1)(f)
- Turtle glass requirements apply in sea turtle nesting areas
- Inspection requests by 3 PM for next business day

DEERFIELD BEACH PRIVATE PROVIDER:
- 25% discount for plan review + inspection
- 15% discount for inspection only
"""
    elif city_key == "pembroke_pines":
        city_context = """
PEMBROKE PINES SPECIFIC REQUIREMENTS:
- Portal: Development HUB (Energov)
- All applications must be NOTARIZED - missing notarization = rejection
- Qualifying contractor must sign (F.S. 713.135)
- Cash NOT accepted - checks/money orders to 'The City of Pembroke Pines'

PEMBROKE PINES NOC THRESHOLDS - DIFFERENT FROM OTHER CITIES:
- General permits: $5,000 (not $2,500!)
- A/C repair/replacement: $15,000 (much higher!)

PEMBROKE PINES PLAN SUBMISSION:
- Two (2) sets of plans required for ALL in-person permits
- Online uploads must be BATCHED by trade - one file per discipline:
  * All Structural sheets in ONE file
  * All Mechanical sheets in ONE file
  * All Electrical sheets in ONE file
  * All Plumbing sheets in ONE file

PEMBROKE PINES ROOFING - CRITICAL:
- ALL roofs require NEW flashing - stucco stop and surface mount ONLY
- Maximum residential permit fee is $500 regardless of roof cost
- Roof-to-wall connection affidavit required for buildings $300,000+ value
- Flashing requirements strictly enforced - will fail inspection without new flashing

PEMBROKE PINES SPECIAL RULES:
- Landscape Affidavit required for ALL exterior work
- Revisions now require permit application with cost (effective 3/7/2024)
- After-the-Fact permits NO LONGER ALLOWED as Owner/Builder (May 1, 2024)
- 25-Year Building Safety Inspection (formerly 40 years)
- After 2nd review rejection for same violation: 20% penalty
- Permit card must be accessible OUTSIDE property
"""
    elif city_key == "hollywood":
        city_context = """
HOLLYWOOD SPECIFIC REQUIREMENTS:
- Portal: ePermitsOneStop (BCLA/ACCELA)
- Building Department CLOSED ON FRIDAYS
- Applications must be signed AND notarized
- HOA Affidavit MANDATORY for all residential permits
- Use QLess for consultation appointments (Mon-Thu 7:30-9:30 AM)

HOLLYWOOD NOC REQUIREMENTS:
- General: $2,500 threshold
- A/C repair/replacement: $7,500 threshold
- NOC required before FIRST INSPECTION can be scheduled

HOLLYWOOD PLAN REVIEW:
- 30 working day review period
- Does NOT include Planning, Zoning, Engineering, or Fire review time
- Permit applications become NULL after 60 days if no action taken
- Job value verified against R.S. Means Building Construction Cost Data

HOLLYWOOD OWNER-BUILDER RESTRICTION:
- Cannot sell house/duplex for 1 YEAR after final inspection

HOLLYWOOD SPECIAL DISTRICTS:
- Chain link fencing NOT permitted in RAC, TOC (front yard), or Historic District
- PVC fencing NOT permitted in Historic District front yard
- Tree removal permit from Engineering required for ALL properties
- Landscape sub-permit required for new construction

HOLLYWOOD EXPRESS PERMITS:
- Available for simple A/C changeouts
- Available for electrical service changes
- Torque Certificate Affidavit required for certain electrical work

HOLLYWOOD MARINE:
- Seawall must meet wind load specifications
- Verify framing meets uplift and lateral forces
- Multiple agency approvals: City, Broward EPD, FL DEP, possibly Army Corps
"""
    elif city_key == "miramar":
        city_context = """
MIRAMAR SPECIFIC REQUIREMENTS:
- Portal: Online Permitting System
- Building Department CLOSED ON FRIDAYS
- Applications must be in BLACK INK
- Do NOT highlight any information on plans - will be REJECTED
- All documents must be in TRUE PDF format

MIRAMAR MANDATORY AFFIDAVITS:
- Construction Debris Removal Affidavit MANDATORY for ALL permits
- HOA Affidavit required EVEN IF property is NOT in an HOA
- Affidavit of Identical Documents required for digitally signed plans

MIRAMAR DEBRIS REQUIREMENT - CRITICAL:
- Debris MUST be removed by Waste Pro of Florida ONLY
- City Ordinance Section 18-7
- Failure to comply = Code violation with fines/penalties

MIRAMAR NOC THRESHOLDS - DIFFERENT:
- General permits: $5,000 (not $2,500!)
- A/C repair/replacement: $15,000 (much higher!)
- NOC must be recorded PRIOR to Building Dept submittal

MIRAMAR PLAN REQUIREMENTS:
- FOUR (4) sets of plans required for engineered plans
- Only NEW Broward County Uniform Permit Application accepted
- Old form versions will be REJECTED
- Schedule of Values required for permit pricing

MIRAMAR PRE-SUBMITTAL:
- EPD approval required BEFORE Building Dept submittal
- Allow 1 week for elevator approval
- ERC Letter + Impact Fee Receipt required for new construction

MIRAMAR QUICK SERVICE:
- Available for: Fence, Driveway, Shed, Re-Roof, Patio Slab
- Windows/Doors, Shutters, Screen Enclosures
- A/C changeout, Electrical service change, Water heater
- Maximum 5 permits per contractor

MIRAMAR PRIVATE PROVIDER:
- 35% discount for plan review + inspections
- 20% discount for inspections only

MIRAMAR FEES:
- After 3rd plan review: $500 flat fee per discipline
- Expedited Review: $300 residential, $600 commercial per discipline
"""
    elif city_key == "plantation":
        city_context = """
PLANTATION SPECIFIC REQUIREMENTS:
- Portal: Broward ePermits
- Application must be signed and notarized by QUALIFIER
- Walk-Thru permits: Mon, Wed, Fri 8-10 AM only (3 permit limit per person)
- Insurance COI must list 'City of Plantation' as Certificate Holder

PLANTATION WORK HOURS:
- Monday-Friday: 7 AM - 8 PM
- Saturday: 7 AM - 8 PM (pile-driving 8 AM - 5:30 PM only)
- NO WORK on Sundays or holidays (City Ordinance Chapter 16, Sec 16-2)

PLANTATION ROUTING - SKIP ZONING FOR:
- A/C changeouts - go DIRECTLY to Building Division
- Re-roofing - go DIRECTLY to Building Division
- Interior work

PLANTATION CRITICAL REQUIREMENTS:
- Demolition permits MUST include Building AND Electrical permits together
- Plenum ceilings require specs on Structural, Electrical, Mechanical AND Plumbing plans
- Pre-fab buildings MUST have State approved drawings (Miami-Dade or Florida State)
- Product Approvals must be stamped 'approved' by Architect of record
- Plans must be mechanically reproduced - hand-drawn plans rejected

PLANTATION SPECIAL RULES:
- Preliminary Review SUSPENDED as of 05/16/2024
- COA/HOA/POA approval NOT required for building permit (effective 05/08/2023)
- Temporary Power requires notarized signatures from owner, GC, AND electrical contractor
- Burglar alarms (SFR) require registration permit from Plantation Police Dept
- Marine work requires US Longshoreman's and Harbor Workers insurance

PLANTATION FEES:
- $20 application fee
- $10 per page of plans (first page free)
- Fast Track available with $1,000 cost recovery account
- Work without permit = 100% penalty fee added
"""
    elif city_key == "sunrise":
        city_context = """
SUNRISE SPECIFIC REQUIREMENTS:
- Portal: sunrisefl.gov/openforbusiness
- Signed Checklist is REQUIRED - most common rejection reason!
- Professional Day: Wednesdays 8 AM - Noon (walk-in with Plans Examiners)
- Contractor registration expires September 30th ANNUALLY

SUNRISE TWO-STEP PROCESS:
Step 1: Broward County ePermits (broward.org/epermits) for:
- Demolition, additions, alterations, new construction

Step 2: City of Sunrise after County approval

SUNRISE - GO DIRECTLY TO BUILDING (skip Zoning):
- Re-roofing
- Interior renovations
- Fencing
- Interior plumbing repairs
- Interior electrical repairs
- A/C changeouts

SUNRISE - REQUIRES ZONING FIRST:
- New construction
- Additions
- Alterations
- Exterior elevation changes

SUNRISE CRITICAL REQUIREMENTS:
- Energy calculations must be in 2 SETS
- Special Inspection forms must be signed by BOTH inspector AND Owner
- Truss drawings need Engineer seal AND Architect/Engineer of record acceptance
- Schedule inspections by 3 PM one day in advance
- Call Chief Inspectors between 8:00-8:30 AM for specific times

SUNRISE PROCESSING TIMES:
- Simple permits (fence, re-roof): ~2 days if correct
- Single-family permits: 2-3 weeks if correct
- Delays usually from plans not promptly corrected

SUNRISE PENALTIES:
- Work without permit = DOUBLE fee charged
"""
    elif city_key == "west_palm_beach":
        city_context = """
WEST PALM BEACH SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Portal: EPL Civic Access Portal
- NOT in HVHZ (Palm Beach County - still need Florida Product Approvals)
- Insurance MUST list: 'City of West Palm Beach, 401 Clematis Street, West Palm Beach, FL 33401'

WEST PALM BEACH NOC REQUIREMENTS:
- NOC threshold: $5,000 general, $15,000 for HVAC
- Must be recorded at Palm Beach County Recording Department
- Include permit number when emailing recorded NOC to ds@wpb.org
- Recording Location: 205 North Dixie Highway (4th Floor), West Palm Beach

WEST PALM BEACH SPECIAL REQUIREMENTS:
- Flood zone verification required before application
- Elevation certificates required for certain flood zones
- Historic district properties require additional Planning Division review
- All materials must have Florida Product Approval
- Mobility Fee adopted May 2025 for Downtown projects

WEST PALM BEACH INSPECTIONS:
- Find your inspector at 7:30 AM via Civic Access Portal → Today's Inspections
- Call inspector for 2-hour window
- Long wait times 11:30 AM - 2:30 PM - avoid these hours
- Building Chief Inspector: (561) 805-6670

WEST PALM BEACH ROOFING TIP:
- Schedule Building Miscellaneous inspection BEFORE starting work
- Take extensive photos during installation
- Discuss expectations with inspector first

WEST PALM BEACH PENALTIES:
- Work without permit = 4x permit fee (Stop Work penalty)
- Expired permits: Email expiredpermits@wpb.org early if selling property
"""
    elif city_key == "boynton_beach":
        city_context = """
BOYNTON BEACH SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Portal: SagesGov (new permits) / Click2Gov (legacy permits)
- NOT in HVHZ (Palm Beach County)
- All documents must be UNPROTECTED - system rejects password-protected files!

BOYNTON BEACH PORTAL ROUTING:
- Permit #21-2804 or LOWER: Use Legacy system
- New permits: Use SagesGov portal

BOYNTON BEACH NOC REQUIREMENTS:
- NOC threshold: $5,000 general, $15,000 for HVAC repair/replacement
- Email recorded NOC to: BuildingM@bbfl.us

BOYNTON BEACH INSPECTIONS - CRITICAL:
- Requests after 3:00 PM NOT scheduled next day
- Need permit application number AND 7-digit PIN

BOYNTON BEACH RESUBMITTAL FEES - WARNING:
- Wait for ALL reviews before submitting corrections
- Same-issue rejections trigger escalating fees:
  * 1st resubmittal: Free
  * 2nd (same comments): $75 min OR 10% of original fee
  * 3rd+ (same comments): 4x original permit fee!

BOYNTON BEACH STREAMLINED PERMITS:
- A/C, Water Heater: $55 each
- Streamlined Program: $250/year for expedited processing
- Expedited review for: Bioscience, medical, pharmaceutical, affordable housing, green-certified

BOYNTON BEACH PENALTIES:
- Work without permit = 4x permit fee
"""
    elif city_key == "delray_beach":
        city_context = """
DELRAY BEACH SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Portal: eServices Portal
- NOT in HVHZ (Palm Beach County)
- ALL permits now DIGITAL ONLY through eServices
- Paper submissions incur $25 scanning fee
- All documents must be unprotected

DELRAY BEACH EXPRESS PERMITS (3 days):
- A/C Change-out
- Water Heater Replacement
- Re-roof
- Emergency A/C and water heater can be permitted within 24 hours of work completion!

DELRAY BEACH NOC REQUIREMENTS:
- NOC threshold: $5,000 general, $15,000 for HVAC
- Recording Location: Palm Beach County Court House, 200 W. Atlantic Ave

DELRAY BEACH HISTORIC DISTRICT - CRITICAL:
- Many properties unknowingly in Historic Districts - CHECK FIRST!
- Use Historic District Map on city website
- Historic Preservation Acknowledgement form required
- HP review can add significant time to approval
- May require Historic Preservation Board review

DELRAY BEACH SPECIAL REQUIREMENTS:
- 180 days without inspection = permit expired
- Contractors must register BEFORE permit submittal
- Owner-builders must appear IN PERSON
- Check flood zone - required for any CO/CC issuance
- Right-of-Way: Check Table MBL-1 of Mobile Element before new construction
- Green Building: New construction 15,000+ SF requires certification

DELRAY BEACH PENALTIES:
- After-the-fact permit = 3x normal permit cost
- Stop work notice issued by Code Enforcement
- May require third-party engineering if work concealed
"""
    else:
        city_context = f"""
GENERAL SOUTH FLORIDA REQUIREMENTS:
- Florida Building Code 8th Edition (2023) in effect
- Florida Product Approval required for exterior products
- Check if in HVHZ zone - Broward County is HVHZ, Palm Beach generally is not
- Environmental approvals may be required before local permit
"""

    gotchas_text = ""
    if gotchas:
        gotchas_text = (
            "\n\nKNOWN GOTCHAS FOR THIS CITY (common rejection reasons):\n"
            + "\n".join([f"⚠️ {g}" for g in gotchas[:10]])
        )

    tips_text = ""
    if tips:
        tips_text = "\n\nPERMIT OFFICE TIPS:\n" + "\n".join([f"💡 {t}" for t in tips])

    prompt = f"""You are an expert South Florida permit analyst with 20+ years of experience reviewing permit applications for Broward and Palm Beach counties. You have deep, specific knowledge of {city_name}'s building department requirements, processes, and common rejection reasons.

TASK: Analyze this permit package ({file_count} files) for a {permit_name} application in {city_name}.

{city_context}

REQUIRED DOCUMENTS FOR THIS PERMIT TYPE:
{reqs}
{gotchas_text}
{tips_text}

UPLOADED DOCUMENTS CONTENT:
{text}

ANALYSIS INSTRUCTIONS:

1. **Document Identification**: Carefully identify EACH document in the package:
   - Document titles, headers, stamps, signatures
   - Professional seals (architect, engineer, contractor)
   - Dates and revision numbers
   - Drawing sheet numbers and titles
   - Look for NOAs (Notice of Acceptance) for products

2. **City-Specific Compliance**: Check for {city_name}-specific requirements:
   - Correct forms used for this city
   - Proper insurance certificate holder name (if visible)
   - Required signatures and notarizations
   - Pre-submittal approvals (EPD, etc.)

3. **Completeness Check**: For EACH required document:
   - Is it present? Look for explicit evidence
   - Is it properly signed/sealed where required?
   - Is it dated within acceptable range (typically within 1 year)?
   - Does it match the project scope?

4. **Technical Review**: Check for common issues:
   - Missing signatures or seals on drawings
   - Incomplete NOC (Notice of Commencement)
   - Energy calculations (Manual J for residential HVAC)
   - Product approvals (NOAs) for roofing, windows, doors
   - Survey not signed/sealed or outdated
   - Site plan missing setbacks, property lines, or flood zone info
   - Load calculations for electrical/HVAC
   - Missing contractor license info
   - HVHZ compliance for impact products

5. **Scoring Guidelines**:
   - 90-100: All documents present, properly executed, ready to submit
   - 70-89: Minor issues, likely approved with small corrections
   - 50-69: Significant gaps, will need resubmission
   - Below 50: Major documents missing, not ready for submission

Return your analysis as JSON:
{{
    "summary": "2-3 sentence executive summary of package readiness for {city_name}",
    "overall_status": "READY|NEEDS_ATTENTION|INCOMPLETE",
    "compliance_score": <number 0-100>,
    "documents_found": [
        {{"name": "document name", "status": "complete|incomplete|needs_signature", "notes": "specific details"}}
    ],
    "missing_documents": [
        {{"name": "document name", "importance": "critical|important|recommended", "notes": "why needed for {city_name}"}}
    ],
    "critical_issues": [
        {{"issue": "description", "severity": "high|medium|low", "fix": "how to resolve"}}
    ],
    "recommendations": [
        "Specific actionable recommendation 1",
        "Specific actionable recommendation 2"
    ],
    "city_specific_warnings": [
        "Any {city_name}-specific issues that could cause rejection"
    ],
    "permit_office_tips": "Specific tips for submitting to {city_name} building department"
}}

IMPORTANT: 
- Be thorough but practical - focus on what will actually cause permit delays in {city_name}
- If you can't find evidence of a document, mark it as missing
- {city_name} permit office is strict about signatures, seals, and proper forms
- Flag any city-specific requirements that aren't met"""

    try:
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        resp = msg.content[0].text

        # Parse JSON
        import re

        for pattern in [r"```json\s*([\s\S]*?)\s*```", r"\{[\s\S]*\}"]:
            matches = re.findall(pattern, resp)
            for m in matches:
                try:
                    parsed = json.loads(m.strip() if m.strip().startswith("{") else m)
                    if "summary" in parsed or "compliance_score" in parsed:
                        # Ensure backwards compatibility - flatten documents_found if needed
                        if parsed.get("documents_found") and isinstance(
                            parsed["documents_found"][0], dict
                        ):
                            parsed["documents_found_detailed"] = parsed[
                                "documents_found"
                            ]
                            parsed["documents_found"] = [
                                d.get("name", str(d)) for d in parsed["documents_found"]
                            ]
                        if parsed.get("missing_documents") and isinstance(
                            parsed["missing_documents"][0], dict
                        ):
                            parsed["missing_documents_detailed"] = parsed[
                                "missing_documents"
                            ]
                            parsed["missing_documents"] = [
                                d.get("name", str(d))
                                for d in parsed["missing_documents"]
                            ]
                        if parsed.get("critical_issues") and isinstance(
                            parsed["critical_issues"][0], dict
                        ):
                            parsed["critical_issues_detailed"] = parsed[
                                "critical_issues"
                            ]
                            parsed["critical_issues"] = [
                                d.get("issue", str(d))
                                for d in parsed["critical_issues"]
                            ]
                        return parsed
                except:
                    continue

        return {
            "summary": resp[:500],
            "compliance_score": 50,
            "overall_status": "NEEDS_REVIEW",
        }
    except Exception as e:
        return {"error": str(e), "overall_status": "ERROR"}


@app.on_event("startup")
async def startup():
    print("🚀 Flo Permit v1.4.0 Started")
    print(f"   API Key: {'✅' if get_api_key() else '❌'}")
    print(f"   JWT Key: {'✅' if os.getenv('JWT_SECRET_KEY') else '❌'}")
    print(f"   Resend Key: {'✅' if os.getenv('RESEND_API_KEY') else '❌'}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
