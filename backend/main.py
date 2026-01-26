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
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'stripe_customer_id' not in columns:
        print("📦 Adding Stripe columns to users table...")
        for col_sql in [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_ends_at TIMESTAMP"
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
async def forgot_password(request_data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Request a password reset email"""
    try:
        # Always return success to prevent email enumeration
        user = db.query(User).filter(User.email == request_data.email).first()
        
        if user:
            # Invalidate any existing reset tokens for this user
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False
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
            "message": "If an account exists with this email, you will receive a password reset link."
        }
    except Exception as e:
        print(f"❌ Forgot password error: {str(e)}")
        print(traceback.format_exc())
        # Still return success for security
        return {
            "success": True,
            "message": "If an account exists with this email, you will receive a password reset link."
        }


@app.post("/api/auth/reset-password")
async def reset_password(request_data: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using token"""
    try:
        # Find the token
        reset_token = db.query(PasswordResetToken).filter(
            PasswordResetToken.token == request_data.token,
            PasswordResetToken.used == False
        ).first()
        
        if not reset_token:
            raise HTTPException(status_code=400, detail="Invalid or expired reset link")
        
        if is_token_expired(reset_token.expires_at):
            reset_token.used = True
            db.commit()
            raise HTTPException(status_code=400, detail="Reset link has expired. Please request a new one.")
        
        # Validate new password
        if len(request_data.new_password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        
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
            "message": "Password has been reset successfully. You can now log in with your new password."
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
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    """Get admin dashboard statistics"""
    user_id = get_current_user_id(authorization)
    require_admin(user_id, db)
    
    from sqlalchemy import func
    
    # Total users
    total_users = db.query(User).count()
    
    # Users this month
    first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    new_users_this_month = db.query(User).filter(User.created_at >= first_of_month).count()
    
    # Total analyses
    total_analyses = db.query(AnalysisHistory).count()
    
    # Analyses this month
    analyses_this_month = db.query(AnalysisHistory).filter(AnalysisHistory.created_at >= first_of_month).count()
    
    # Average compliance score
    avg_score = db.query(func.avg(AnalysisHistory.compliance_score)).scalar() or 0
    
    # API requests today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    api_requests_today = db.query(APILog).filter(APILog.created_at >= today_start).count()
    
    # API requests this month
    api_requests_month = db.query(APILog).filter(APILog.created_at >= first_of_month).count()
    
    # Most popular cities
    popular_cities = db.query(
        AnalysisHistory.city,
        func.count(AnalysisHistory.id).label('count')
    ).group_by(AnalysisHistory.city).order_by(func.count(AnalysisHistory.id).desc()).limit(5).all()
    
    # Most popular permit types
    popular_permits = db.query(
        AnalysisHistory.permit_type,
        func.count(AnalysisHistory.id).label('count')
    ).group_by(AnalysisHistory.permit_type).order_by(func.count(AnalysisHistory.id).desc()).limit(5).all()
    
    # Recent users
    recent_users = db.query(User).order_by(User.created_at.desc()).limit(10).all()
    
    # Recent analyses
    recent_analyses = db.query(AnalysisHistory).order_by(AnalysisHistory.created_at.desc()).limit(10).all()
    
    # API endpoint stats
    endpoint_stats = db.query(
        APILog.endpoint,
        func.count(APILog.id).label('count'),
        func.avg(APILog.response_time_ms).label('avg_time')
    ).filter(APILog.created_at >= first_of_month).group_by(APILog.endpoint).order_by(func.count(APILog.id).desc()).limit(10).all()
    
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
        "popular_permits": [{"permit_type": p, "count": cnt} for p, cnt in popular_permits],
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
            message=form_data.message
        )
        if success:
            return {"success": True, "message": "Message sent! We'll get back to you soon."}
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
                "features": ["50 analyses/month", "Priority AI analysis", "Priority support", "Analysis history"],
                "popular": True,
            },
            {
                "id": "business",
                "name": "Business",
                "price": 99,
                "period": "month",
                "analyses": -1,
                "features": ["Unlimited analyses", "Priority AI analysis", "Dedicated support", "Analysis history", "Team features (coming soon)"],
            },
        ]
    }


@app.post("/api/stripe/create-checkout-session")
async def create_checkout_session(
    tier: str = Form(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db)
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
                metadata={"user_id": str(user.id)}
            )
            user.stripe_customer_id = customer.id
            db.commit()
        
        # Create checkout session
        session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price": STRIPE_PRICES[tier],
                "quantity": 1,
            }],
            mode="subscription",
            success_url=f"{FRONTEND_URL}?payment=success&tier={tier}",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            metadata={
                "user_id": str(user.id),
                "tier": tier,
            }
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
    authorization: str = Header(None),
    db: Session = Depends(get_db)
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
    authorization: str = Header(None),
    db: Session = Depends(get_db)
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
        first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        analyses_this_month = db.query(AnalysisHistory).filter(
            AnalysisHistory.user_id == user.id,
            AnalysisHistory.created_at >= first_of_month
        ).count()
        
        tier = user.subscription_tier or "free"
        tier_limit = TIER_LIMITS.get(tier, 3)
        
        return {
            "tier": tier,
            "analyses_this_month": analyses_this_month,
            "analyses_limit": tier_limit,
            "analyses_remaining": max(0, tier_limit - analyses_this_month) if tier_limit < 999999 else -1,
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
        first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        analyses_this_month = db.query(AnalysisHistory).filter(
            AnalysisHistory.user_id == user.id,
            AnalysisHistory.created_at >= first_of_month
        ).count()
        
        tier_limit = TIER_LIMITS.get(user.subscription_tier, 3)
        if analyses_this_month >= tier_limit:
            raise HTTPException(
                status_code=403, 
                detail=f"Monthly limit reached ({tier_limit} analyses). Please upgrade your plan."
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
    """Analyze with Claude"""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    reqs = "\n".join([f"- {item}" for item in requirements.get("items", [])])

    if len(text) > 200000:
        text = text[:200000] + "\n[truncated]"

    prompt = f"""Analyze this permit package ({file_count} files) for {requirements.get("name", "permit")}.

REQUIREMENTS:
{reqs}

DOCUMENTS:
{text}

Analyze the documents and identify:
1. Which required documents ARE present and correct
2. Which required documents are MISSING
3. Any critical issues or problems found
4. Recommendations to improve the package

Return JSON:
{{
    "summary": "brief summary of the permit package status",
    "overall_status": "READY|NEEDS_ATTENTION|INCOMPLETE",
    "compliance_score": 0-100,
    "documents_found": ["list of required documents that ARE present and appear correct - be specific about what you found"],
    "missing_documents": ["list of required documents that are MISSING"],
    "critical_issues": ["any problems or issues found in the submitted documents"],
    "recommendations": ["specific recommendations to improve or complete the package"]
}}"""

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