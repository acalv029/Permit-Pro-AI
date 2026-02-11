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
from datetime import datetime, timedelta
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
from gemini_provider import analyze_with_gemini, get_google_key, parse_analysis_json

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
# RECAPTCHA CONFIGURATION
# ============================================================================

RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")


async def verify_recaptcha(token: str, action: str = None) -> bool:
    """Verify reCAPTCHA v3 token"""
    if not RECAPTCHA_SECRET_KEY:
        print("⚠️ RECAPTCHA_SECRET_KEY not set - skipping verification")
        return True  # Skip if not configured

    if not token:
        print("⚠️ No reCAPTCHA token provided")
        return True  # Allow if frontend didn't send token (graceful degradation)

    try:
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": RECAPTCHA_SECRET_KEY,
                    "response": token,
                },
            )
            result = response.json()

            success = result.get("success", False)
            score = result.get("score", 0)

            print(
                f"🤖 reCAPTCHA: success={success}, score={score}, action={result.get('action')}"
            )

            # Score threshold: 0.5 is Google's recommended default
            # 1.0 = definitely human, 0.0 = definitely bot
            if success and score >= 0.3:  # Being lenient at 0.3
                return True

            print(f"⚠️ reCAPTCHA failed: score too low ({score})")
            return False
    except Exception as e:
        print(f"❌ reCAPTCHA verification error: {e}")
        return True  # Allow on error (don't block legitimate users)


# ============================================================================
# STRIPE CONFIGURATION
# ============================================================================

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICES = {
    "pro": "price_1SzRiSJuq6kN4g8CTycjBM4o",
    "business": "price_1SzRlFJuq6kN4g8C06KWetjV",
    "single": "price_1SzRlwJuq6kN4g8CId3bCjec",
}

TIER_LIMITS = {
    "free": 3,
    "pro": 30,
    "business": 999999,
    "single": 1,
}
SINGLE_ANALYSIS_PRICE = 1599

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


def detect_permit_type_from_text(text: str) -> str:
    """Auto-detect permit CATEGORY from document text. AI will determine specific subtype."""
    text_lower = text.lower()

    # Simple category detection - AI will figure out the specific type
    categories = {
        "structural": [
            "roof",
            "window",
            "door",
            "fence",
            "pool",
            "addition",
            "renovation",
            "construction",
            "demolition",
            "sign",
            "screen",
            "awning",
            "concrete",
            "driveway",
            "shed",
            "garage",
            "shutter",
            "building permit",
        ],
        "electrical": [
            "electrical",
            "panel",
            "circuit",
            "wiring",
            "generator",
            "solar",
            "pv",
            "photovoltaic",
            "alarm",
            "low voltage",
            "service change",
            "meter",
        ],
        "mechanical": [
            "hvac",
            "air condition",
            "a/c",
            "ac ",
            "heat pump",
            "ductwork",
            "furnace",
            "condenser",
            "air handler",
            "mechanical",
            "tonnage",
            "seer",
            "ahri",
        ],
        "plumbing": [
            "plumbing",
            "water heater",
            "pipe",
            "drain",
            "sewer",
            "fixture",
            "backflow",
            "irrigation",
            "gas line",
            "tankless",
            "water meter",
        ],
        "marine": [
            "dock",
            "pier",
            "seawall",
            "bulkhead",
            "boat lift",
            "davit",
            "marine",
            "pile",
            "shoreline",
        ],
    }

    scores = {}
    for category, keywords in categories.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > 0:
            scores[category] = score

    if scores:
        return max(scores, key=scores.get)
    return "structural"  # Default to structural


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


class SinglePurchase(Base):
    """One-time homeowner permit analysis purchases"""

    __tablename__ = "single_purchases"

    id = Column(Integer, primary_key=True, index=True)
    purchase_uuid = Column(String(36), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False, index=True)
    city = Column(String(100), nullable=False)
    permit_type = Column(String(100), nullable=False)
    stripe_payment_intent = Column(String(255), nullable=True)
    stripe_session_id = Column(String(255), nullable=True)
    payment_status = Column(String(50), default="pending")  # pending, paid, refunded
    analysis_id = Column(String(36), nullable=True)  # Links to completed analysis
    analysis_used = Column(Boolean, default=False)
    amount_cents = Column(Integer, default=1599)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # 30 days to use after purchase


class Review(Base):
    """User reviews and ratings"""

    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    name = Column(String(100), nullable=False)
    role = Column(String(100), nullable=True)  # e.g., "General Contractor", "Homeowner"
    city = Column(String(100), nullable=True)
    stars = Column(Integer, nullable=False)  # 1-5
    review_text = Column(Text, nullable=False)
    is_approved = Column(Boolean, default=False)  # Admin must approve before showing
    is_featured = Column(Boolean, default=False)  # Show in featured rotator
    created_at = Column(DateTime, default=datetime.utcnow)


class AIUsageLog(Base):
    """Track AI API usage and costs per analysis"""

    __tablename__ = "ai_usage_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    analysis_uuid = Column(String(36), nullable=True)
    model = Column(String(100), nullable=False)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    cost_cents = Column(Integer, default=0)  # Estimated cost in cents
    city = Column(String(100), nullable=True)
    permit_type = Column(String(100), nullable=True)
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

    # Ensure ai_usage_logs table exists
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS ai_usage_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    analysis_uuid VARCHAR(36),
                    model VARCHAR(100) NOT NULL,
                    input_tokens INTEGER DEFAULT 0,
                    output_tokens INTEGER DEFAULT 0,
                    total_tokens INTEGER DEFAULT 0,
                    cost_cents INTEGER DEFAULT 0,
                    city VARCHAR(100),
                    permit_type VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            )
        print("✅ AI usage logs table ready")
    except Exception as e:
        print(f"⚠️ AI usage table note: {e}")


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
        name = full_name.split()[0] if full_name else "there"

        params = {
            "from": "Flo Permit <noreply@flopermit.com>",
            "to": [email],
            "subject": "Welcome to Flo Permit — Let's get your permits right 🎉",
            "html": f"""
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #000000;">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #06b6d4, #10b981); padding: 40px 30px; text-align: center; border-radius: 0 0 20px 20px;">
                    <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 800;">Welcome to Flo Permit!</h1>
                    <p style="color: rgba(255,255,255,0.85); margin: 10px 0 0; font-size: 15px;">AI-Powered Permit Analysis for South Florida</p>
                </div>
                
                <!-- Body -->
                <div style="padding: 35px 30px; background: #111827;">
                    <h2 style="color: #ffffff; font-size: 22px; margin-top: 0;">Hey {name}! 👋</h2>
                    <p style="color: #9ca3af; font-size: 16px; line-height: 1.6;">
                        Thanks for joining Flo Permit. You now have access to AI-powered permit document analysis across <strong style="color: #06b6d4;">26 cities</strong> in Broward, Palm Beach, and Miami-Dade counties.
                    </p>
                    
                    <!-- Free Plan Info -->
                    <div style="background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 20px; margin: 25px 0;">
                        <h3 style="color: #10b981; margin: 0 0 12px; font-size: 16px;">🎁 Your Free Plan Includes:</h3>
                        <table style="width: 100%; color: #d1d5db; font-size: 14px;">
                            <tr><td style="padding: 6px 0;">✅ 3 permit analyses per month</td></tr>
                            <tr><td style="padding: 6px 0;">✅ City-specific requirements checklist</td></tr>
                            <tr><td style="padding: 6px 0;">✅ Missing document identification</td></tr>
                            <tr><td style="padding: 6px 0;">✅ Compliance scoring</td></tr>
                            <tr><td style="padding: 6px 0;">✅ Actionable recommendations</td></tr>
                        </table>
                    </div>

                    <!-- How It Works -->
                    <h3 style="color: #ffffff; font-size: 18px;">Getting Started Is Easy:</h3>
                    <table style="width: 100%; color: #9ca3af; font-size: 15px; line-height: 1.8;">
                        <tr>
                            <td style="padding: 8px 0; vertical-align: top; width: 35px;"><span style="background: linear-gradient(135deg, #06b6d4, #10b981); color: #000; padding: 2px 8px; border-radius: 50%; font-weight: bold; font-size: 13px;">1</span></td>
                            <td style="padding: 8px 0;"><strong style="color: #e5e7eb;">Upload</strong> your permit documents (PDFs, images, plans)</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; vertical-align: top;"><span style="background: linear-gradient(135deg, #06b6d4, #10b981); color: #000; padding: 2px 8px; border-radius: 50%; font-weight: bold; font-size: 13px;">2</span></td>
                            <td style="padding: 8px 0;"><strong style="color: #e5e7eb;">Select</strong> your city and permit type</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; vertical-align: top;"><span style="background: linear-gradient(135deg, #06b6d4, #10b981); color: #000; padding: 2px 8px; border-radius: 50%; font-weight: bold; font-size: 13px;">3</span></td>
                            <td style="padding: 8px 0;"><strong style="color: #e5e7eb;">Get your report</strong> — compliance score, checklist, and recommendations in seconds</td>
                        </tr>
                    </table>
                    
                    <!-- CTA Button -->
                    <div style="text-align: center; margin: 35px 0 25px;">
                        <a href="{FRONTEND_URL}" style="background: linear-gradient(135deg, #06b6d4, #10b981); color: #000000; padding: 16px 40px; text-decoration: none; border-radius: 12px; font-weight: 800; font-size: 16px; display: inline-block;">
                            Start Your First Analysis →
                        </a>
                    </div>

                    <!-- Need More -->
                    <div style="background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 20px; margin: 25px 0; text-align: center;">
                        <p style="color: #d1d5db; font-size: 14px; margin: 0 0 8px;">Need more than 3 analyses?</p>
                        <p style="color: #9ca3af; font-size: 13px; margin: 0;">
                            <a href="{FRONTEND_URL}" style="color: #06b6d4; text-decoration: none; font-weight: 600;">Pro Plan — $29.99/mo</a> for 30 analyses &nbsp;|&nbsp;
                            <a href="{FRONTEND_URL}" style="color: #06b6d4; text-decoration: none; font-weight: 600;">Single Analysis — $15.99</a> one-time
                        </p>
                    </div>
                    
                    <p style="color: #6b7280; font-size: 14px; line-height: 1.6;">
                        Questions? Just reply to this email or reach us at <a href="mailto:support@flopermit.com" style="color: #06b6d4; text-decoration: none;">support@flopermit.com</a>
                    </p>
                </div>
                
                <!-- Footer -->
                <div style="padding: 25px 30px; text-align: center; border-top: 1px solid #1f2937;">
                    <p style="color: #4b5563; font-size: 12px; margin: 0 0 8px;">
                        © 2026 Flo Permit by ADC Builders — South Florida Permit Analysis
                    </p>
                    <p style="color: #374151; font-size: 11px; margin: 0;">
                        Serving 26 cities across Broward, Palm Beach & Miami-Dade Counties
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
            "to": ["toshygluestick@gmail.com"],
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
        # Verify reCAPTCHA
        if not await verify_recaptcha(user_data.recaptcha_token, "register"):
            raise HTTPException(
                status_code=400,
                detail="reCAPTCHA verification failed. Please try again.",
            )

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
        # Verify reCAPTCHA
        if not await verify_recaptcha(user_data.recaptcha_token, "login"):
            raise HTTPException(
                status_code=400,
                detail="reCAPTCHA verification failed. Please try again.",
            )

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
    print("🔍 Admin stats endpoint called")
    import traceback
    from sqlalchemy import func

    # Auth check - extract token from "Bearer <token>" header
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid authorization header"
        )

    token = authorization.replace("Bearer ", "")
    print(f"🔍 Token: {token[:20]}...")

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(user_id)
    except Exception as e:
        print(f"❌ Token decode error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

    print(f"🔍 User ID: {user_id}")
    require_admin(user_id, db)
    print("🔍 Admin check passed")

    try:
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
        today_start = datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        api_requests_today = (
            db.query(APILog).filter(APILog.created_at >= today_start).count()
        )

        # API requests this month
        api_requests_month = (
            db.query(APILog).filter(APILog.created_at >= first_of_month).count()
        )

        # Most popular cities
        popular_cities = (
            db.query(
                AnalysisHistory.city, func.count(AnalysisHistory.id).label("count")
            )
            .group_by(AnalysisHistory.city)
            .order_by(func.count(AnalysisHistory.id).desc())
            .limit(5)
            .all()
        )

        # Most popular permit types
        popular_permits = (
            db.query(
                AnalysisHistory.permit_type,
                func.count(AnalysisHistory.id).label("count"),
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

        # AI Usage Stats - default to zeros
        ai_usage_today = (0, 0, 0, 0)
        ai_usage_month = (0, 0, 0, 0)
        try:
            ai_usage_today = db.query(
                func.sum(AIUsageLog.input_tokens),
                func.sum(AIUsageLog.output_tokens),
                func.sum(AIUsageLog.cost_cents),
                func.count(AIUsageLog.id),
            ).filter(AIUsageLog.created_at >= today_start).first() or (0, 0, 0, 0)

            ai_usage_month = db.query(
                func.sum(AIUsageLog.input_tokens),
                func.sum(AIUsageLog.output_tokens),
                func.sum(AIUsageLog.cost_cents),
                func.count(AIUsageLog.id),
            ).filter(AIUsageLog.created_at >= first_of_month).first() or (0, 0, 0, 0)
        except Exception as ai_err:
            print(f"AI usage query failed (table may not exist): {ai_err}")

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
            "ai_costs": {
                "today": {
                    "analyses": ai_usage_today[3] if ai_usage_today[3] else 0,
                    "input_tokens": ai_usage_today[0] if ai_usage_today[0] else 0,
                    "output_tokens": ai_usage_today[1] if ai_usage_today[1] else 0,
                    "cost_cents": ai_usage_today[2] if ai_usage_today[2] else 0,
                    "cost_dollars": round(
                        (ai_usage_today[2] if ai_usage_today[2] else 0) / 100, 2
                    ),
                },
                "this_month": {
                    "analyses": ai_usage_month[3] if ai_usage_month[3] else 0,
                    "input_tokens": ai_usage_month[0] if ai_usage_month[0] else 0,
                    "output_tokens": ai_usage_month[1] if ai_usage_month[1] else 0,
                    "cost_cents": ai_usage_month[2] if ai_usage_month[2] else 0,
                    "cost_dollars": round(
                        (ai_usage_month[2] if ai_usage_month[2] else 0) / 100, 2
                    ),
                },
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
    except Exception as e:
        print(f"❌ Admin stats error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to load stats: {str(e)}")


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
                "id": "single",
                "name": "Single Analysis",
                "price": 15.99,
                "period": "one-time",
                "analyses": 1,
                "features": [
                    "1 permit analysis",
                    "Full checklist included",
                    "30 days to use",
                    "No subscription required",
                ],
                "homeowner": True,
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


@app.post("/api/stripe/create-single-checkout")
async def create_single_checkout(
    email: str = Form(...),
    city: str = Form(...),
    permit_type: str = Form(...),
    db: Session = Depends(get_db),
):
    """Create Stripe checkout session for single homeowner analysis - no account needed"""
    try:
        purchase_uuid = str(uuid.uuid4())

        # Create Stripe checkout session for one-time payment
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            customer_email=email,
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": f"Permit Analysis - {city}",
                            "description": f"One-time {permit_type} permit analysis for {city}. Includes full checklist and 30 days to use.",
                        },
                        "unit_amount": SINGLE_ANALYSIS_PRICE,  # $15.99 in cents
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url=f"{FRONTEND_URL}?purchase=success&purchase_id={purchase_uuid}",
            cancel_url=f"{FRONTEND_URL}?purchase=cancelled",
            metadata={
                "purchase_uuid": purchase_uuid,
                "city": city,
                "permit_type": permit_type,
                "type": "single_analysis",
            },
        )

        # Create pending purchase record
        purchase = SinglePurchase(
            purchase_uuid=purchase_uuid,
            email=email,
            city=city,
            permit_type=permit_type,
            stripe_session_id=session.id,
            payment_status="pending",
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db.add(purchase)
        db.commit()

        return {
            "checkout_url": session.url,
            "session_id": session.id,
            "purchase_id": purchase_uuid,
        }

    except stripe.error.StripeError as e:
        print(f"❌ Stripe error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment error: {str(e)}")
    except Exception as e:
        print(f"❌ Single checkout error: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Checkout error: {str(e)}")


@app.get("/api/single-purchase/{purchase_uuid}")
async def get_single_purchase(purchase_uuid: str, db: Session = Depends(get_db)):
    """Get single purchase status and details"""
    purchase = (
        db.query(SinglePurchase)
        .filter(SinglePurchase.purchase_uuid == purchase_uuid)
        .first()
    )

    if not purchase:
        raise HTTPException(status_code=404, detail="Purchase not found")

    # Get permit requirements for checklist
    city_key = get_city_key(purchase.city)
    requirements = get_permit_requirements(city_key, purchase.permit_type)

    return {
        "purchase_uuid": purchase.purchase_uuid,
        "email": purchase.email,
        "city": purchase.city,
        "permit_type": purchase.permit_type,
        "payment_status": purchase.payment_status,
        "analysis_used": purchase.analysis_used,
        "analysis_id": purchase.analysis_id,
        "expires_at": purchase.expires_at.isoformat() if purchase.expires_at else None,
        "checklist": requirements.get("documents", []) if requirements else [],
        "gotchas": requirements.get("gotchas", [])[:5] if requirements else [],
    }


@app.post("/api/analyze-single/{purchase_uuid}")
@limiter.limit("5/minute")
async def analyze_single_purchase(
    request: Request,
    purchase_uuid: str,
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
):
    """Analyze permit for a single purchase - marks purchase as used after success"""
    purchase = (
        db.query(SinglePurchase)
        .filter(SinglePurchase.purchase_uuid == purchase_uuid)
        .first()
    )

    if not purchase:
        raise HTTPException(status_code=404, detail="Purchase not found")

    if purchase.payment_status != "paid":
        raise HTTPException(status_code=402, detail="Payment not completed")

    if purchase.analysis_used:
        raise HTTPException(
            status_code=400,
            detail="Analysis already used. Single purchases allow only one analysis.",
        )

    if purchase.expires_at and purchase.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=400,
            detail="Purchase expired. Single purchases are valid for 30 days.",
        )

    # Process the analysis (similar to regular analyze endpoint)
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

        city_key = get_city_key(purchase.city)
        requirements = get_permit_requirements(city_key, purchase.permit_type)
        if not requirements:
            requirements = get_permit_requirements(city_key, "building")

        analysis = analyze_folder_with_claude(
            "\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=None,
            analysis_uuid=analysis_id,
            db_session=db,
            tier="premium",
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        # Mark purchase as used
        purchase.analysis_used = True
        purchase.analysis_id = analysis_id
        db.commit()

        return {
            "analysis_id": analysis_id,
            "city": purchase.city,
            "permit_type": requirements.get("name", purchase.permit_type),
            "files_analyzed": len(processed_files),
            "total_size": format_file_size(total_size),
            "file_tree": file_tree,
            "analysis": analysis,
            "checklist": requirements.get("documents", []),
            "single_purchase": True,
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


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
        # Check if this is a single purchase
        metadata = data.get("metadata", {})
        if metadata.get("type") == "single_analysis":
            # Single purchase payment completed
            purchase_uuid = metadata.get("purchase_uuid")
            purchase = (
                db.query(SinglePurchase)
                .filter(SinglePurchase.purchase_uuid == purchase_uuid)
                .first()
            )
            if purchase:
                purchase.payment_status = "paid"
                purchase.stripe_payment_intent = data.get("payment_intent")
                db.commit()
                print(f"✅ Single purchase {purchase_uuid} paid for {purchase.city}")
        else:
            # Subscription payment successful
            customer_id = data.get("customer")
            subscription_id = data.get("subscription")
            tier = metadata.get("tier", "pro")

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
        # Broward County (HVHZ)
        "Fort Lauderdale": {
            "key": "fort_lauderdale",
            "county": "Broward",
            "waterfront": True,
        },
        "Pompano Beach": {
            "key": "pompano_beach",
            "county": "Broward",
            "waterfront": True,
        },
        "Hollywood": {"key": "hollywood", "county": "Broward", "waterfront": True},
        "Coral Springs": {"key": "coral_springs", "county": "Broward"},
        "Coconut Creek": {"key": "coconut_creek", "county": "Broward"},
        "Lauderdale-by-the-Sea": {
            "key": "lauderdale_by_the_sea",
            "county": "Broward",
            "waterfront": True,
        },
        "Deerfield Beach": {
            "key": "deerfield_beach",
            "county": "Broward",
            "waterfront": True,
        },
        "Pembroke Pines": {"key": "pembroke_pines", "county": "Broward"},
        "Lighthouse Point": {
            "key": "lighthouse_point",
            "county": "Broward",
            "waterfront": True,
        },
        "Weston": {"key": "weston", "county": "Broward"},
        "Davie": {"key": "davie", "county": "Broward"},
        "Plantation": {"key": "plantation", "county": "Broward"},
        "Sunrise": {"key": "sunrise", "county": "Broward"},
        "Miramar": {"key": "miramar", "county": "Broward"},
        "Margate": {"key": "margate", "county": "Broward"},
        "Tamarac": {"key": "tamarac", "county": "Broward"},
        "Oakland Park": {"key": "oakland_park", "county": "Broward"},
        # Palm Beach County
        "Boca Raton": {"key": "boca_raton", "county": "Palm Beach", "waterfront": True},
        "Lake Worth Beach": {
            "key": "lake_worth_beach",
            "county": "Palm Beach",
            "waterfront": True,
        },
        "Delray Beach": {
            "key": "delray_beach",
            "county": "Palm Beach",
            "waterfront": True,
        },
        "Boynton Beach": {
            "key": "boynton_beach",
            "county": "Palm Beach",
            "waterfront": True,
        },
        "West Palm Beach": {
            "key": "west_palm_beach",
            "county": "Palm Beach",
            "waterfront": True,
        },
        "Wellington": {"key": "wellington", "county": "Palm Beach"},
        # Miami-Dade County (HVHZ)
        "Miami": {"key": "miami", "county": "Miami-Dade", "waterfront": True},
        "Hialeah": {"key": "hialeah", "county": "Miami-Dade"},
        "Miami Gardens": {"key": "miami_gardens", "county": "Miami-Dade"},
        "Kendall": {"key": "kendall", "county": "Miami-Dade"},
        "Homestead": {"key": "homestead", "county": "Miami-Dade"},
        "North Miami": {"key": "north_miami", "county": "Miami-Dade"},
        "Miami Beach": {
            "key": "miami_beach",
            "county": "Miami-Dade",
            "waterfront": True,
        },
    }
    return {"cities": cities}


# ============================================================================
# REVIEWS
# ============================================================================


@app.post("/api/reviews")
async def submit_review(
    request: Request, authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Submit a new review (requires login)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization[7:]
    payload = decode_access_token(token)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    data = await request.json()
    name = data.get("name", "").strip()
    role = data.get("role", "").strip()
    city = data.get("city", "").strip()
    stars = data.get("stars", 5)
    review_text = data.get("review_text", "").strip()

    if not name or not review_text:
        raise HTTPException(status_code=400, detail="Name and review text are required")

    if stars < 1 or stars > 5:
        raise HTTPException(status_code=400, detail="Stars must be between 1 and 5")

    review = Review(
        user_id=user_id,
        name=name,
        role=role or None,
        city=city or None,
        stars=stars,
        review_text=review_text,
        is_approved=False,
        is_featured=False,
    )
    db.add(review)
    db.commit()

    return {
        "success": True,
        "message": "Thank you! Your review has been submitted for approval.",
    }


@app.get("/api/reviews")
async def get_approved_reviews(db: Session = Depends(get_db)):
    """Get all approved reviews for public display"""
    reviews = (
        db.query(Review)
        .filter(Review.is_approved == True)
        .order_by(Review.created_at.desc())
        .limit(20)
        .all()
    )
    return {
        "reviews": [
            {
                "id": r.id,
                "name": r.name,
                "role": r.role,
                "city": r.city,
                "stars": r.stars,
                "review_text": r.review_text,
                "is_featured": r.is_featured,
                "created_at": r.created_at.isoformat(),
            }
            for r in reviews
        ]
    }


@app.get("/api/admin/reviews")
async def get_all_reviews_admin(
    authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Get all reviews for admin (including pending)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization[7:]
    payload = decode_access_token(token)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    reviews = db.query(Review).order_by(Review.created_at.desc()).all()
    return {
        "reviews": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "name": r.name,
                "role": r.role,
                "city": r.city,
                "stars": r.stars,
                "review_text": r.review_text,
                "is_approved": r.is_approved,
                "is_featured": r.is_featured,
                "created_at": r.created_at.isoformat(),
            }
            for r in reviews
        ]
    }


@app.put("/api/admin/reviews/{review_id}")
async def update_review_admin(
    review_id: int,
    request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """Admin: approve/feature/delete reviews"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization[7:]
    payload = decode_access_token(token)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    data = await request.json()

    if "is_approved" in data:
        review.is_approved = data["is_approved"]
    if "is_featured" in data:
        review.is_featured = data["is_featured"]

    db.commit()
    return {"success": True}


@app.delete("/api/admin/reviews/{review_id}")
async def delete_review_admin(
    review_id: int, authorization: str = Header(None), db: Session = Depends(get_db)
):
    """Admin: delete a review"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization[7:]
    payload = decode_access_token(token)
    user_id = int(payload.get("sub"))

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    db.delete(review)
    db.commit()
    return {"success": True}


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
    tier: str = Form("standard"),
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

        # Handle auto-detect permit type
        if permit_type == "auto" or not permit_type:
            # AI will detect the permit type from the documents
            detected_type = detect_permit_type_from_text("\n".join(all_text))
            permit_type = detected_type

        requirements = get_permit_requirements(city_key, permit_type)
        if not requirements:
            # Fallback to building if detection fails
            requirements = get_permit_requirements(city_key, "building")
            if not requirements:
                raise HTTPException(
                    status_code=404,
                    detail=f"No requirements for {city} - {permit_type}",
                )

        # Determine AI tier based on subscription
        ai_tier = "standard"  # default: Gemini Flash (cheap)
        if user and user.subscription_tier in ("pro", "business"):
            ai_tier = "premium"  # Claude Sonnet (better quality)

        analysis = analyze_folder_with_claude(
            "\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=user_id,
            analysis_uuid=analysis_id,
            db_session=db,
            tier=ai_tier,
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
    text: str,
    requirements: dict,
    api_key: str,
    file_count: int,
    user_id: int = None,
    analysis_uuid: str = None,
    db_session=None,
    tier: str = "standard",
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
- Dock limits: <100ft waterway = 6ft max, >=100ft = 8ft max projection
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
- NO WORK on Sundays or holidays

PLANTATION ROUTING - SKIP ZONING FOR:
- A/C changeouts, Re-roofing, Interior work - go DIRECTLY to Building Division

PLANTATION CRITICAL REQUIREMENTS:
- Demolition permits MUST include Building AND Electrical permits together
- Product Approvals must be stamped 'approved' by Architect of record
- Plans must be mechanically reproduced - hand-drawn plans rejected

PLANTATION SPECIAL RULES:
- COA/HOA/POA approval NOT required for building permit (effective 05/08/2023)
- Marine work requires US Longshoreman's and Harbor Workers insurance

PLANTATION FEES:
- $20 application fee, $10 per page of plans (first page free)
- Fast Track available with $1,000 cost recovery account
- Work without permit = 100% penalty fee added
"""
    elif city_key == "sunrise":
        city_context = """
SUNRISE SPECIFIC REQUIREMENTS:
- Portal: sunrisefl.gov/openforbusiness
- Signed Checklist is REQUIRED - most common rejection reason!
- Professional Day: Wednesdays 8 AM - Noon
- Contractor registration expires September 30th ANNUALLY

SUNRISE TWO-STEP PROCESS:
Step 1: Broward County ePermits for demolition, additions, alterations, new construction
Step 2: City of Sunrise after County approval

SUNRISE - GO DIRECTLY TO BUILDING (skip Zoning):
- Re-roofing, Interior renovations, Fencing, Interior plumbing/electrical repairs, A/C changeouts

SUNRISE CRITICAL REQUIREMENTS:
- Energy calculations must be in 2 SETS
- Truss drawings need Engineer seal AND Architect/Engineer of record acceptance
- Schedule inspections by 3 PM one day in advance

SUNRISE PENALTIES:
- Work without permit = DOUBLE fee charged
"""
    elif city_key == "west_palm_beach":
        city_context = """
WEST PALM BEACH SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
- Portal: EPL Civic Access Portal
- NOT in HVHZ (Palm Beach County)
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
    elif city_key == "miami":
        city_context = """
CITY OF MIAMI SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
- Portal: iBuild / ePlan (ProjectDox)
- FULLY DIGITAL system - All plans must be digitally signed and sealed
- All of Miami-Dade is HVHZ - minimum 175 mph wind load design
- Miami-Dade Product Approval (NOA) required - NOT just Florida Product Approval!

MIAMI DERM REQUIREMENT - CRITICAL:
- DERM approval required BEFORE city permit for:
  * New buildings and additions
  * Commercial interior renovation/remodeling
  * Commercial re-roofs
  * Commercial pools
  * Land clearing and demolition
  * Tank upgrades, installations, and removals
- Submit to County FIRST, then to City

MIAMI NOC REQUIREMENTS:
- NOC threshold: $2,500 general, $7,500 for HVAC
- Record at: Miami-Dade County Recorder's Office, 22 NW 1st Street
- Phone: (305) 275-1155

MIAMI CONTRACTOR REQUIREMENTS:
- Registration takes 2-3 business days, no cost
- Permit expediters must also register per City Ordinance 14279
- Valid State of Florida OR Miami-Dade County license required

MIAMI HOURS & TIPS:
- Hours: Mon-Fri 7:30 AM - 4:30 PM (closes to public at 3:30 PM)
- Track inspector route in real-time via City website
- Permits valid for 180 days from issuance

MIAMI SPECIAL PROGRAMS:
- Homeowner Assistance Program: (305) 710-0605 / hoabuilding@miamigov.com
- Concierge Program for large commercial: concierge@miamigov.com
- Joint Plan Review for Affordable Housing (no cost)

MIAMI HISTORIC PROPERTIES:
- Check if property is historically designated BEFORE applying
- Certificate of Appropriateness (COA) may be required
- Contact Historic Preservation Office if unsure
"""
    elif city_key == "hialeah":
        city_context = """
CITY OF HIALEAH SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
- Portal: Tyler CSS (Citizens Self Service)
- All of Miami-Dade is HVHZ - minimum 175 mph wind load
- Miami-Dade Product Approval (NOA) required for all exterior products

HIALEAH NOTARIZATION - STRICTLY ENFORCED:
- Permit application MUST be notarized
- Owner affidavits MUST be notarized
- For condos: Association Authorization Letter with president's signature NOTARIZED
- Missing notarization = automatic rejection

HIALEAH OWNER-BUILDER - STRICT REQUIREMENTS:
- Must reside at the property
- Valid FL driver's license with property address required
- Warranty deed and homestead exemption may be required
- Tenant improvements limited to: 500 sq ft or less AND under $5,000 for non-structural only

HIALEAH DERM REQUIREMENT:
- DERM approval required BEFORE city permit for commercial projects
- Submit to Miami-Dade County FIRST

HIALEAH NOC REQUIREMENTS:
- NOC threshold: $2,500 general (or $5,000), $7,500 for HVAC
- Record at Miami-Dade County Recorder's Office

HIALEAH HOURS - NOTE LUNCH CLOSURE:
- Mon-Fri 7:30 AM - 11:15 AM
- CLOSED for lunch
- Mon-Fri 12:30 PM - 3:15 PM

HIALEAH INSPECTIONS:
- Check routed inspections: apps.hialeahfl.gov/building/DailyRoutedInspections.aspx
- Once permit issued, contractor/owner-builder responsible for requesting all inspections

HIALEAH SPECIAL PROGRAMS:
- Buildings 25+ years require milestone inspections (recertification)
- Amnesty Program available - contact Building Department for eligibility
"""
    elif city_key == "miami_gardens":
        city_context = """
MIAMI GARDENS SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
- Portal: Tyler CSS (Citizens Self Service)
- All of Miami-Dade is HVHZ - minimum 175 mph wind load
- Miami-Dade Product Approval (NOA) required for all exterior products

⚠️ MIAMI GARDENS IS CLOSED ON FRIDAYS!
- Hours: Mon-Thu 7:00 AM - 6:00 PM ONLY
- NO services on Fridays

MIAMI GARDENS PLAN REQUIREMENTS:
- Two (2) sets of plans required
- Must be drawn to scale
- Must be signed and sealed by FL PE or architect (if applicable)

MIAMI GARDENS DERM - VERY COMMON REJECTION:
- DERM approval required BEFORE city permit for:
  * New buildings
  * Nonresidential additions
  * Commercial interior alterations
  * Commercial re-roofs
  * Commercial pools
  * Land clearing
  * Demolition

MIAMI GARDENS ADDITIONAL APPROVALS:
- DBPR approval required for restaurants
- Miami-Dade County Health Dept approval for: ALFs, day cares, hospitals, schools

MIAMI GARDENS NOC REQUIREMENTS:
- NOC threshold: $2,500 general, $7,500 for HVAC
- NOC must be present at job site for FIRST INSPECTION

MIAMI GARDENS INSPECTIONS:
- Requests before 3:00 PM = scheduled for next business day
- Requests after 3:00 PM = scheduled for TWO business days out
- To cancel: Email buildingpermitquestions@miamigardens-fl.gov before 9:00 AM

MIAMI GARDENS PROCESSING TIMES:
- Residential permits: Average 14 working days
- Commercial permits: Average 28 working days
- Review by 3-7 disciplines: Structural, Electrical, Mechanical, Plumbing, Zoning, Building, DERM, Fire, Public Works
- Permits expire after 180 days without inspection

MIAMI GARDENS RECERTIFICATION:
- Buildings 25-30 years require milestone inspections
- Parking lot guardrail recertification required
- Parking lot illumination recertification required
"""
    elif city_key == "kendall":
        city_context = """
KENDALL (UNINCORPORATED MIAMI-DADE COUNTY) - HVHZ:
- Portal: EPS Portal (miamidade.gov/Apps/RER/EPSPortal)
- Permits through Miami-Dade County Permitting and Inspection Center (PIC)
- Property folio numbers start with "30" for unincorporated MDC
- Application must be signed AND notarized (Yellow Form)

KENDALL/MDC CRITICAL REQUIREMENTS:
- Miami-Dade NOA required - NOT just Florida Product Approval!
- DERM approval required BEFORE building permit for most projects
- Work without permit = 100% penalty (DOUBLE fee) - strictly enforced!

KENDALL E-PERMITTING:
- Available 7 days/week from 2 AM to 5 PM for trade permits
- Most permits can be submitted online through EPS Portal

KENDALL NOC:
- NOC threshold: $2,500 general, $7,500 for HVAC
- Record at: Miami-Dade County Recorder's Office, 22 NW 1st Street
- Phone: (305) 275-1155

KENDALL HVAC REQUIREMENTS:
- SEER ratings must meet current minimums (SEER2 15 for split systems)
- Load calculations REQUIRED if changing equipment size - can't just "match existing"
- Condensate drain must be visible and accessible

KENDALL ELECTRICAL REQUIREMENTS:
- Pool bonding strictly enforced - ALL metal within 5 feet must be bonded
- AFCI required in bedrooms, living rooms, hallways
- GFCI required in bathrooms, kitchens, garages, outdoors, within 6ft of sinks
- Smoke detectors: interconnected, hardwired with battery backup

KENDALL ROOFING - HVHZ:
- Peel-and-stick underlayment REQUIRED for shingle roofs
- Max 2 roof layers - often must tear off existing
- NOA must cover SPECIFIC system, not just individual products
- Verify NOA covers your wind zone and building height

KENDALL COST SAVINGS:
- 15% refund available for permits not requiring rework (request within 180 days)
- Private Provider option: 65% fee reduction for their portion
- Green Building Expedited Review for LEED/FGBC projects $50k+

KENDALL MARINE CONSTRUCTION:
- Requires BOTH Building Permit AND Class I Environmental Permit from DERM
- Seawall cap must be minimum 6 inches above adjacent grade
- Unencapsulated polystyrene (Styrofoam) is PROHIBITED
- Multiple agency approvals can take 6-12 months total
"""
    elif city_key == "homestead":
        city_context = """
CITY OF HOMESTEAD SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
- Portal: EPL-B.U.I.L.D (NEW - launched October 2025)
- Legacy projects (before Oct 2025) use Community Plus - DON'T MIX SYSTEMS!
- Application must be signed AND notarized
- Remote Online Notary (RON) accepted

⚠️ HOMESTEAD FILE NAMING - CRITICAL:
- Files MUST follow format: BD-YY-XXXXX-PT-R-DISCIPLINE
- Example: BD-25-12345-PT-R-ARCHITECTURAL
- Files AUTO-REJECTED if naming convention not followed!
- NO special characters: # % & {{ }} / \\ ? < > * $ ! ' : @ " + ` | = ~ ( )

HOMESTEAD PLAN REQUIREMENTS:
- Leave upper-right corner blank for City seal
- 2"x2" for letter size, 3"x3" for larger plans
- Group plans by discipline - separate PDF per discipline
- All pages of one NOA must be grouped together in single PDF
- Calculations grouped with corresponding discipline

HOMESTEAD COUNTY APPROVALS - REQUIRED:
- DERM, WASD, Impact Fee approvals through MIAMI-DADE COUNTY portal
- Must obtain M# number from Miami-Dade before City permit finalized
- County fees paid SEPARATELY from City fees

HOMESTEAD REVIEW TIME:
- Initial review: approximately 14 business days
- Re-submittals may occur multiple times
- Upfront fees required before review begins

HOMESTEAD OWNER-BUILDER - STRICT:
- Must prove knowledge and ability (TEST ADMINISTERED)
- Must be owner's personal residence, not for sale
- Limited to ONE permit per 24-month period for new construction
- Owner must appear IN PERSON for document review
- No permit if existing violation on property

HOMESTEAD CONSTRUCTION RULES:
- Construction hours: 7:00 AM - 7:00 PM ONLY
- Construction debris must be removed by licensed hauler
- Streets and neighboring properties must be kept clean
- Equipment/materials stored on property, not public right-of-way

HOMESTEAD NOC:
- Must be recorded at 22 N.W. 1st Street, 1st floor
- Phone: (305) 275-1155 ext 6
- Recorded NOC must be posted at job site
"""
    elif city_key == "oakland_park":
        city_context = """
OAKLAND PARK SPECIFIC REQUIREMENTS (BROWARD COUNTY - HVHZ):
Contact: 954-630-4350 | building@oaklandparkfl.gov | 5399 N. Dixie Hwy, Suite #3, Oakland Park, FL 33334
Hours: Monday-Friday 7:30 AM - 4:30 PM
Uses Broward County Uniform Building Permit Application for ALL permit types.
Permits submitted through City's online CSS portal or in person.

OAKLAND PARK GENERAL REQUIREMENTS (ALL PERMITS):
- Broward County Uniform Building Permit Application, filled out completely and NOTARIZED
- Contractor must be REGISTERED with City of Oakland Park (Contractor Registration Form required)
- Valid contractor license + Broward County Certificate of Competency or State of Florida license
- Certificate of Insurance (liability), valid minimum 6 months
- Workers' Comp Insurance or valid exemption
- NOC required for job value > $2,500 (for A/C and heat: > $7,500)
- NOC recorded at Broward County Records Dept, 115 S. Andrews Ave, Fort Lauderdale
- NOC must be posted at job site before first inspection
- Owner Builder Disclosure Statement required if owner doing work (FL Statute 489.103(7)(a))
- Owner must personally appear, sign, and have application notarized
- ALL documents must be PDFs only - NO .img, .jpeg, .tiff accepted
- Plans combined as one attachment, permit app as separate PDF
- Must include estimated job value, quantity, and square footage
- Two sets of plans drawn to scale, signed and sealed by FL-licensed architect or engineer
- Two site plans and two surveys showing scope, property lines, easements, setbacks, elevations
- Site plan must include pervious/impervious percentage
- Two copies Product Approvals/NOA with wind load calculations
- Two copies energy calculations and heating/cooling load specs when required
- Impervious/Pervious Calculation Form
- Work without permit = DOUBLE permit fee + possible demolition

⚠️ OAKLAND PARK EPD REQUIREMENT - CRITICAL:
- Broward County Environmental Protection Division (EPD) approval required BEFORE permit for:
  * All new buildings, demolitions, additions to non-residential
  * Interior alterations with change of use, commercial re-roofs
  * Slabs > 250 sq ft, detached additions to residential
- Must apply within 30 days of EPD approval

OAKLAND PARK BUILDING PERMITS:
- Two sets plans signed/sealed by FL architect or engineer
- Fire sprinkler plans for buildings > 3 stories
- Truss Drawings signed/sealed when trusses involved
- DRC (Development Review Committee) approved plans if applicable
- Environmental Review Procedure Form
- Trade applications (Electrical, Plumbing, Mechanical) must be approved before master permit
- Elevator: Broward County Elevator Division approval required
- Fire sprinkler/alarm: hydraulic calculations and cut sheets required
- Blower Door Test Requirements for energy compliance
- Survey required (except interior-only work)

OAKLAND PARK ELECTRICAL PERMITS:
- Electrical Service Form required
- Plans showing electrical layout for new construction/major alterations

OAKLAND PARK PLUMBING PERMITS:
- Backflow Test Report when applicable
- 30-Day Temporary Testing Form when applicable

OAKLAND PARK MECHANICAL/HVAC PERMITS:
- BORA A/C Replacements Form for A/C changeouts
- Two copies energy calculations and heating/cooling load calculations
- Manufacturer's specifications
- NOC threshold is $7,500 for heat and A/C systems

OAKLAND PARK ROOFING PERMITS (HVHZ):
- Roofing Application Form
- Roofing HVHZ Uniform Permit Application
- Roof Calculations (HVC)
- Roof Truss Shop Drawings, signed/sealed by engineer with calculations
- Roof sketch showing all levels, sections, drains, scuppers, overflow, dimensions
- Clearly identify elevated pressure zones and parapet locations
- Product Approvals/NOA with wind load calculations
- Hurricane Mitigation Affidavit
- Affidavit of Compliance with Roof Decking Attachment and Secondary Water Barrier
- EPD approval required for commercial re-roofs

OAKLAND PARK FENCE & GATE PERMITS:
- Two sets plans showing fence, setback dimensions, height, linear feet
- Two copies surveys showing easements
- Florida Building Code Prescriptive Wood & Chain Link Fence Requirements form
- Swimming Pool Safety Act forms if pool barrier
- Fences for New or Existing Pools form when applicable
- Easement Agreement if installing in easement
- Drainage District Approval Letter if property borders waterway
- Swale Acknowledgment Form
- Max height 6 feet from grade residential
- Pool fences: no opening > 1/2 inch within 18 inches of release mechanism (FBC 454.2.17)

OAKLAND PARK DRIVEWAY/PATIO/WALKWAY PERMITS:
- Driveway Walks Patio Packet (R-1 and R-2 Requirements)
- Impervious/Pervious Calculation Form
- Swale Acknowledgment Form
- ROW Driveway/Swale Detail if connecting to public ROW
- Engineering ROW Permit Application for work in ROW

OAKLAND PARK POOL/SPA/HOT TUB PERMITS:
- Multiple permits required: Building, Electrical, Plumbing
- Residential Swimming Pool, Spa, and Hot Tub Safety Act Form - MANDATORY
- Pool Safety Form (barrier/safety method)
- Plans showing pool location, dimensions, setbacks, barriers, equipment, plumbing/electrical
- Product Approvals for pool barrier and safety equipment
- Separate electrical and plumbing trade permits required
- NOC for each trade

OAKLAND PARK WINDOW/DOOR/SHUTTER PERMITS:
- Retrofit Window and Door Schedule
- Product Approvals/NOA with wind load calculations
- Manufacturer's installation instructions

OAKLAND PARK SIGN PERMITS:
- Sign Worksheets
- Must conform to FBC Chapter 16, Section 1619 wind pressure
- Illuminated signs must meet National Electric Code
- DMUD Sign Design Guidelines if in Downtown Mixed-Use District
- Temporary Signs/Banners and Political Signs are separate applications

OAKLAND PARK SHED/ACCESSORY STRUCTURES:
- FL approved drawings with sealed anchoring specs (prefab)
- Signed/sealed plans by FL architect/engineer (site-built)
- R-1 and R-2 Shed Requirements
- Section 24-68 Code of Ordinances

OAKLAND PARK SCREEN ENCLOSURES:
- Two sets plans signed/sealed by registered designer
- Product Approvals/NOA with wind load calculations

OAKLAND PARK DEVELOPMENT PERMITS:
- Six collated plan sets 24"x36", two signed/sealed, folded to 8.5"x11"
- Traffic Generation Data/Impact Analysis
- Service Demand Analysis and PSIA (residential)
- Public Notice Sign Affidavit
- Unity of Title Agreement
- Opinion of Title
- Neighborhood meeting required before submission
"""
    elif city_key == "north_miami":
        city_context = """
CITY OF NORTH MIAMI SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
Contact: 305-895-9820 ext. 18001/18002 | 12340 NE 8th Avenue, North Miami, FL 33161
Uses City of North Miami Building Permit Application (NOT Broward County form).
Separate application for ROW/Utility permits.

NORTH MIAMI GENERAL REQUIREMENTS (ALL PERMITS):
- City of North Miami Building Permit Application (primary app for all except ROW/Utility)
- Application must be signed by BOTH property owner AND licensed contractor
- Building Cost Affidavit required
- Valid State of Florida license or Miami-Dade County Certificate of Competency
- Certificate of Insurance (liability), valid minimum 6 months
- Workers' Comp Insurance or valid exemption
- NOC required for job value > $2,500 or if obtaining financing
- NOC recorded at Miami-Dade County, 44 West Flagler St, 8th Floor, Miami, FL 33130
- NOC must be posted at job site per FL Statute 713.135
- Owner Builder Affidavit and Disclosure Statement Form if owner doing work
- Cannot have ANY outstanding building violations - application will not be approved
- All required plans, data, AND fees must be submitted TOGETHER - incomplete apps not processed
- Estimated Construction Value must be based on actual cost including profit and overhead
- Separate permits required for: Electrical, Plumbing, Signs, Pools, Boilers, Tanks, A/C, Roofing, Shutters, Windows, Doors
- Permit does NOT relieve owner from HOA approval obligations
- Construction hours: No loud noise 8PM-7AM. No special equipment 5PM-7AM weekdays or 5PM-9AM Sundays
- Portable toilets require separate permit
- DERM/Miami-Dade WASD approval required for sewer work
- Dept of Health approval required for septic tank work
- Equipment/materials stored at least 10 feet from ROW edge

NORTH MIAMI BUILDING PERMITS:
- Addition Checklist from city applies
- Two sets plans signed/sealed by FL architect or engineer
- Survey showing existing conditions, property lines, setbacks, proposed work
- Site plan with drainage details
- Energy calculations when required
- Special Inspector Form for threshold buildings
- Trade permits (Electrical, Plumbing, Mechanical) submitted separately
- Fire-Rated Joint Penetration Affidavit for fire-rated assemblies
- Early Start Request Application available if needed

NORTH MIAMI ROOFING PERMITS:
- 2023 Roof Packet - comprehensive roofing package REQUIRED
- Hurricane Mitigation Affidavit
- Roofing Permit Affidavit
- Product Approvals/NOA for all materials
- Roof calculations and truss shop drawings, signed/sealed by engineer
- Roof sketch showing all sections, drains, scuppers, dimensions

NORTH MIAMI FENCE PERMITS:
- FENCE Checklist from city required
- Must submit the MATCHING fence detail packet for fence type:
  * Aluminum/Iron/Steel Fence detail
  * Chain Link Fence Construction Standards
  * Standard Horizontal Aluminum Fence detail
  * Wood Fence detail
  * Or own specific fence detail
- Residential Fence Requirements form
- Dumpster Enclosures Permit Instructions if for dumpster
- Pool Safety Form if fence serves as pool barrier

NORTH MIAMI POOL/SPA PERMITS:
- Pool-Spa Checklist from city
- Pool Safety Form - MANDATORY (FL Residential Swimming Pool and Hot Tub Safety Act)
- Plans showing pool location, dimensions, setbacks, equipment, plumbing, electrical
- Barrier and safety compliance details
- Separate Electrical and Plumbing trade permits required

NORTH MIAMI BOAT DOCK PERMITS:
- Boat Dock Checklist from city
- Plans signed/sealed by FL engineer showing dock design, dimensions, anchoring
- Survey showing waterfront property lines, existing structures, mean high water line, water depths
- Miami-Dade County DERM Class I Environmental Permit REQUIRED
- Florida DEP General Permit or Individual Permit depending on dock size
- U.S. Army Corps of Engineers permit if applicable
- Environmental impact assessment if required
- Enhanced permits needed if in Outstanding Florida Waters or Aquatic Preserves

NORTH MIAMI DEMOLITION PERMITS:
- Demolition Permit Checklist from city
- Asbestos survey report required for commercial demolition (Miami-Dade County)
- Notice of Demolition/Asbestos Abatement to Miami-Dade 10 working days before start
- Utility disconnection confirmations (water, electric, gas, sewer)

NORTH MIAMI WINDOW/DOOR/SHUTTER PERMITS:
- Window, Door, and Shutter Checklist from city
- Window, Door, and Shutters application/detail form
- Product Approvals/NOA with wind load calculations
- Manufacturer's installation instructions

NORTH MIAMI A/C REPLACEMENT PERMITS:
- Air Conditioning Replacement Sheet required

NORTH MIAMI GENERATOR PERMITS:
- Generator Permitting Requirements Checklist from city
- Underground fuel tanks/pads min 5 feet from property line and principal structure
- In flood districts: min elevation = finish floor of building
- No generator/fuel tank forward of front or corner side
- Electrical permit also required

NORTH MIAMI SIGN PERMITS:
- Sign Requirements Checklist from city
- Electrical permit needed for illuminated signs
- Zoning compliance verification required

NORTH MIAMI CHANGE OF CONTRACTOR:
- Change of Contractor Affidavit and Form/Checklist
- Certified letter of change to previous contractor
- Only property owner may request change for master permit

NORTH MIAMI RECERTIFICATION (30/40-Year):
- Structural and Electrical recertification guidelines (2025)
- Parking lot guardrails and illumination recertification
- Reports by FL-licensed engineer or architect

NORTH MIAMI PLANNING & ZONING:
- Contact Community Planning & Development: 305-893-6511
- DRC meetings: 2nd and 4th Thursday, 2:00 PM
- Pre-application meeting REQUIRED
- Applications by appointment only, 1 week before DRC
- Shadow Study if adjacent to R-1/R-2 properties
- View Study if adjacent to R-1/R-2
- Boundary survey with contours at max 2-foot intervals
"""
    elif city_key == "wellington":
        city_context = """
VILLAGE OF WELLINGTON SPECIFIC REQUIREMENTS (PALM BEACH COUNTY):
Contact: 561-753-2430 | BuildingDocs@wellingtonfl.gov | 12300 Forest Hill Blvd, Wellington, FL 33414
Hours: Mon-Fri 7:00 AM - 4:00 PM | Inspections: 7:00 AM - 3:30 PM
Uses Village of Wellington Building Permit Application (FBC 8th Edition 2023)
All permits processed electronically through ProjectDox

WELLINGTON GENERAL REQUIREMENTS (ALL PERMITS):
- Village of Wellington Building Permit Application, signed by BOTH property owner AND contractor
- Application not complete until all approvals obtained: Planning, Zoning, Engineering, Fire Rescue, Environmental, FL Dept of Health
- Fee Simple Titleholder, Bonding Co, Architect/Engineer, Mortgage Lender info required when aggregate value >= $5,000
- Exception: HVAC repair/replacement under $15,000 exempt from above requirement
- NOC required for direct contract > $5,000 (HVAC: > $15,000)
- NOC must be recorded AND posted before first inspection - NO subsequent inspections without certified copy
- Contractor must be registered with Village using Contractor Registration Packet
- State of Florida license or Palm Beach County CILB certification required
- Owner Builder Affidavit if owner doing work - must personally appear at Building Dept
- All plans/docs must be PDFs - 8.5"x11", 11"x17", or 24"x36" only
- DO NOT change plan size when resubmitting corrections
- One printed set approved plans in Permit Box or on job site
- Permit does not assure HOA compliance - get HOA approval first
- Open permits may result in CILB referral or CBAA action

WELLINGTON RESIDENTIAL NEW CONSTRUCTION:
- New Residential Packet
- Plans signed/sealed by FL architect or engineer
- Survey, site plan with drainage, energy calcs
- Truss drawings signed/sealed when applicable
- New Construction Affidavit
- Building Code Windload/Flood Resistant Design Certification form
- Floodplain Development Packet if in flood zone
- Special Inspector Packet for threshold buildings
- Residential Permission to Stock form when applicable

WELLINGTON COMMERCIAL NEW CONSTRUCTION:
- New Commercial Packet
- Fire Plan Review Application - REQUIRED for all commercial new construction
- Fire Alarm Packet, Fire Sprinkler Packet, Fire Suppression Packet as applicable
- Building Code Windload/Flood Resistant Design Certification form
- Commercial Permission to Stock/Train form when applicable

WELLINGTON ROOFING PERMITS:
- Reroof Packet with Roof Material Worksheet for ALL proposed systems
- FL Product Approval numbers for all materials - different pitches may need different products
- Hurricane Mitigation Affidavit - required upon COMPLETION
- Existing plywood must be re-nailed: min 8d ring-shank at 6" OC before underlayment

WELLINGTON FENCE/WALL PERMITS:
- Fence/Wall Packet
- ARB Approved Fence Form (Architectural Review Board)
- Landscape and Fence Affidavit
- Swimming Pool Barrier Requirements Affidavit if pool barrier

WELLINGTON POOL PERMITS:
- Swimming Pool Packet + Swimming Pool Barrier Packet
- Swimming Pool Barrier Requirements Affidavit - MANDATORY (FL Pool Safety Act)
- Pool sub-permits issued anytime after primary EXCEPT deck permits (must be simultaneous)
- FL Dept of Health approval for public/commercial pools

WELLINGTON WINDOW/DOOR/SHUTTER PERMITS:
- Window, Door & Shutter Packet
- Window and Door Buck Affidavit

WELLINGTON SOLAR PANEL PERMITS:
- Solar Panel Packet
- Structural analysis/engineering letter confirming roof can support load
- Electrical permit also required

WELLINGTON DEMOLITION PERMITS:
- Demolition Packet
- Asbestos Letter and Asbestos Notification Guide forms (Palm Beach County Health Dept)
- Utility disconnection confirmations

WELLINGTON STABLE/MANURE BIN PERMITS (Equestrian):
- Stable and Manure Bin Packet
- Livestock waste must be containerized and covered
- Manure bins must prevent stormwater from discharging waste
- Size based on number of horses and volume
- Planning & Zoning approval if in EOZD (Equestrian Overlay Zoning District)

WELLINGTON ENGINEERING/SITEWORK PERMITS:
- Required for: fill/excavation, paving, grading, drainage, ROW connections
- Culvert/irrigation connections to Acme Improvement District canal
- Closeout: as-built drawings must be approved before final inspection
- Plat applications: Unity of Title, fee simple title opinion, Restrictive Covenants, Utility Easement Consent

WELLINGTON PLANNING & ZONING:
- Contact: 561-753-2511
- Pre-application intake meeting REQUIRED
- Type A1: Administrative (Special Permits, Seasonal Equestrian, Admin Variances, Tree Removal)
- Type A2: Administrative with DRM Certification (Site Plan, Subdivision, Minor Master Plan)
- Type B: Board Review (Variances, Appeals, Rezonings, Development Permits)
- EOZD has additional regulations for Equestrian Preserve Area
"""
    elif city_key == "miami_beach":
        city_context = """
CITY OF MIAMI BEACH SPECIFIC REQUIREMENTS (MIAMI-DADE COUNTY - HVHZ):
Contact: 305-673-7610 | BuildingInfo@miamibeachfl.gov | Homeowner: HomeOwnerBuild@miamibeachfl.gov
City Hall: 1700 Convention Center Dr, 2nd Floor | North Beach Annex: 962 Normandy Dr
Hours: Mon-Fri 8:00 AM - 4:00 PM (closed 12-1 PM lunch) | Inspections: 8:30 AM - 3:30 PM
Uses City of Miami Beach permit application via Civic Access portal
Miami-Dade County approval often required before City plan review complete

MIAMI BEACH GENERAL REQUIREMENTS (ALL PERMITS):
- Permit Application signed and NOTARIZED by owner/rep AND registered contractor
- Permit Application Submittal Checklist - MUST be completed/uploaded with EVERY application
- Contractor must be registered with City of Miami Beach
- Construction Cost Affidavit - required when job value > $5,000
- CPMP (Construction Parking Management Plan) - REQUIRED for jobs >= $250,000
- Affidavit in Lieu of CPMP available for: change of contractor, exact equipment changeout, new sub-permits
- Construction Site Sediment and Erosion Control Affidavit - required for land-disturbing activities
- $144 review fee for jobs >= $250,000
- NOC required for jobs > $5,000
- Plans must comply with Rules for Electronic File Submission
- Master Building Permit required for 2+ trades - then sub-permits issued to individual trades
- Planning & Zoning review required on MOST permits
- Each review cycle = max 15 business days; average 2 cycles to issuance

⚠️ MIAMI BEACH FEMA 50% RULE - CRITICAL:
- When improvements = "substantial improvement" (cost >= 50% market value)
- Structure MUST be brought into FULL compliance with floodplain/building code for NEW construction
- This can significantly increase project scope and cost

MIAMI BEACH RESIDENTIAL NEW CONSTRUCTION:
- Residential New checklist (or w/Phased for large projects)
- Phased Permit allows early phases (foundation, structure) while later phases still under review
- Building Code Windload certification
- Floodplain compliance (Elevation Certificate if flood zone)
- CPMP if job value > $250,000
- Sediment and Erosion Control Affidavit

MIAMI BEACH COMMERCIAL PERMITS:
- Commercial New/Alteration checklist (or w/Phased)
- Condominium Interior Alteration - Single Unit checklist (no structural/exterior)
- Fire plan review - separate checklists for alarm, sprinkler, suppression
- Miami-Dade County Municipal Approval when required

MIAMI BEACH A/C PERMITS:
- Exact Change Out with no ductwork = OTC (Over-the-Counter) same-day permit
- No plans required for exact changeout OTC
- Curb Adaptor for Roof Top Unit has separate checklist

MIAMI BEACH ROOFING PERMITS:
- Residential/Commercial Roofing checklist
- Product Approvals/NOA with wind load calculations
- Hurricane Mitigation Affidavit
- Gutter/Downspout and Waterproofing have separate checklists

MIAMI BEACH MARINE/DOCK PERMITS:
- Residential Marine or Commercial Marine checklist
- Must acquire City process number BEFORE submitting to Miami-Dade DERM
- FL DEP and Army Corps permits if applicable

MIAMI BEACH DEMOLITION PERMITS:
- If in LOCAL HISTORIC DISTRICT or individually designated historic site:
- ALL requests for total demolition require Historic Preservation Board PUBLIC HEARING
- Planning & Zoning approval

MIAMI BEACH SIGN PERMITS:
- Non-Illuminated, Illuminated (Monument/Free-standing), Electrical Sign checklists
- Must comply with City zoning regulations

MIAMI BEACH POOL PERMITS:
- New, Alteration, Finishing, Lifts checklists (Residential/Commercial)
- Pool Safety Act compliance required

MIAMI BEACH SPECIAL EVENTS/TEMPORARY STRUCTURES:
- Extensive special event permitting (Tents, Stages, Structures, Bleachers, Platforms, Trusses)
- Fire Department review required
- Occupant load calculations

MIAMI BEACH HISTORIC PRESERVATION - CRITICAL:
- Certificate of Appropriateness required for modifications in historic districts
- Minor work (repairs, windows, awnings, paint, minor demo) may be staff-approved
- Major work requires Historic Preservation Board hearing
- Board approvals valid 18 months, may extend 1 year
- Variances ONLY for dimensional restrictions - use variances PROHIBITED
- Max height variances > 3 feet PROHIBITED

MIAMI BEACH OTC (SAME-DAY) PERMITS:
- No plans or technical review required
- Signed/notarized app with owner and contractor
- Construction Cost Affidavit if > $5,000
- Violation-related OTC may not be same-day

MIAMI BEACH WALKTHROUGH METHOD:
- Apply in person, routed via Qmatic to each discipline
- If approved, pay and receive permit same day
- Contractor-drawn plans: signed/notarized, job value <= $25,000
- Design professional plans: wet seal or embossed required

MIAMI BEACH EXPEDITED REVIEW:
- Available after at least one review cycle completed
- Requests Mon-Thu by 2:00 PM
- Reviews conducted Saturdays and Sundays ONLY

MIAMI BEACH RECERTIFICATION:
- Required at 40 years after CO, then every 10 years
- Buildings 3+ stories or exceeding area threshold
- Structural and electrical inspections required
- Annual Maintenance Log must be maintained
- Contact: BuildingRecertification@miamibeachfl.gov

MIAMI BEACH GREEN PERMITS:
- Sustainability Fee Program applies
- Chapter 133 City Code green building requirements
- Sea Level Rise and Resiliency Review Criteria apply
"""
    else:
        city_context = f"""
GENERAL SOUTH FLORIDA REQUIREMENTS:
- Florida Building Code 8th Edition (2023) in effect
- Florida Product Approval required for exterior products
- Check if in HVHZ zone - Broward and Miami-Dade are HVHZ, Palm Beach generally is not
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

    prompt = f"""You are an expert South Florida permit analyst with 20+ years of experience reviewing permit applications for Broward, Palm Beach, and Miami-Dade counties. You have deep knowledge of {city_name}'s building department requirements.

TASK: Analyze this permit package ({file_count} files) for {city_name}.

YOUR FIRST JOB: Identify the SPECIFIC permit type from the documents. Don't just say "plumbing" - determine if it's:
- Water heater changeout
- Gas line installation
- Sewer cap/line
- Irrigation system
- Backflow installation
- Fixture replacement
- General plumbing

Similarly for other categories:
- ELECTRICAL: Service change, panel upgrade, generator, solar PV, low voltage/alarm, temporary pole
- MECHANICAL: A/C changeout (same size), new HVAC install, commercial HVAC
- STRUCTURAL: Re-roof, windows/doors, shutters, fence, pool, addition, renovation, new construction, demolition, sign

{city_context}

GENERAL REQUIREMENTS CHECKLIST:
{reqs}
{gotchas_text}
{tips_text}

UPLOADED DOCUMENTS:
{text}

ANALYZE THE DOCUMENTS AND RETURN JSON:
{{
    "summary": "2-3 sentence summary. Be specific about what permit type this is (e.g., 'Water heater replacement permit package for Fort Lauderdale' not just 'Plumbing permit').",
    "detected_permit_type": "SPECIFIC type detected (e.g., 'water_heater_changeout', 'ac_changeout', 're_roof', 'service_upgrade', 'pool', 'fence', etc.)",
    "detected_permit_description": "Human readable (e.g., 'Water Heater Exact Changeout', 'A/C Same-Size Replacement', 'Re-Roof - Tile to Shingle')",
    "overall_status": "READY|NEEDS_ATTENTION|INCOMPLETE",
    "compliance_score": <0-100>,
    "documents_found": [
        {{"name": "document name", "status": "complete|incomplete|needs_signature", "notes": "details"}}
    ],
    "missing_documents": [
        {{"name": "document name", "importance": "critical|important|recommended", "notes": "why needed"}}
    ],
    "critical_issues": [
        {{"issue": "description", "severity": "high|medium|low", "fix": "how to fix"}}
    ],
    "recommendations": ["actionable recommendation 1", "actionable recommendation 2"],
    "city_specific_warnings": ["any {city_name}-specific rejection risks"],
    "permit_office_tips": "tips for {city_name} submission"
}}

SCORING:
- 90-100: Ready to submit
- 70-89: Minor fixes needed
- 50-69: Significant gaps
- Below 50: Major documents missing

Be SPECIFIC about the permit type. Read the documents carefully to identify exactly what work is being done."""

    # STANDARD TIER: Use Gemini Flash (95% cheaper)
    if tier == "standard" and get_google_key():
        try:
            print(f"Using Gemini Flash (standard tier) for {city_name}")
            result = analyze_with_gemini(prompt, max_tokens=4096)

            print(
                f"Gemini Usage: {result['input_tokens']:,} in + {result['output_tokens']:,} out "
                f"= {result['total_tokens']:,} tokens (${result['cost_cents'] / 100:.3f})"
            )

            if db_session:
                try:
                    usage_log = AIUsageLog(
                        user_id=user_id,
                        analysis_uuid=analysis_uuid,
                        model=result["model"],
                        input_tokens=result["input_tokens"],
                        output_tokens=result["output_tokens"],
                        total_tokens=result["total_tokens"],
                        cost_cents=result["cost_cents"],
                        city=city_name,
                        permit_type=permit_name,
                    )
                    db_session.add(usage_log)
                    db_session.commit()
                except Exception as log_err:
                    print(f"Failed to log Gemini usage: {log_err}")

            parsed = parse_analysis_json(result["response_text"])
            parsed["_metadata"] = {
                "provider": "gemini",
                "model": result["model"],
                "tier": "standard",
                "estimated_cost_usd": result["cost_cents"] / 100,
            }
            return parsed

        except Exception as gemini_err:
            print(f"Gemini failed, falling back to Claude: {gemini_err}")

    # PREMIUM TIER: Use Claude Sonnet (or fallback from Gemini failure)
    try:
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        resp = msg.content[0].text

        # Log AI usage and costs
        input_tokens = msg.usage.input_tokens
        output_tokens = msg.usage.output_tokens
        total_tokens = input_tokens + output_tokens
        # Claude Sonnet 4 pricing: $3/1M input, $15/1M output
        # FIXED: divide by 1M first, then convert to cents
        cost_cents = max(
            1, int((input_tokens * 3 + output_tokens * 15) / 1_000_000 * 100)
        )

        print(
            f"📊 AI Usage: {input_tokens:,} in + {output_tokens:,} out = {total_tokens:,} tokens (${cost_cents / 100:.2f})"
        )

        # Save to database if session provided
        if db_session:
            try:
                usage_log = AIUsageLog(
                    user_id=user_id,
                    analysis_uuid=analysis_uuid,
                    model="claude-sonnet-4-20250514",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    total_tokens=total_tokens,
                    cost_cents=cost_cents,
                    city=city_name,
                    permit_type=permit_name,
                )
                db_session.add(usage_log)
                db_session.commit()
            except Exception as log_err:
                print(f"⚠️ Failed to log AI usage: {log_err}")

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
    print(
        f"   Google Key: {'✅' if os.getenv('GOOGLE_API_KEY') else '❌ (Gemini disabled)'}"
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
