"""
PermitPro AI - South Florida Permit Checker API
Production-ready FastAPI backend with user authentication and profiles
"""

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
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_id,
)

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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    analyses = relationship(
        "AnalysisHistory",
        back_populates="user",
        order_by="desc(AnalysisHistory.created_at)",
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


Base.metadata.create_all(bind=engine)
print("✅ Database tables initialized")


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


# ============================================================================
# APP CONFIGURATION
# ============================================================================

app = FastAPI(
    title="PermitPro AI",
    description="AI-powered permit analysis for South Florida",
    version="1.3.0",
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
    "https://permit-pro-ai.vercel.app",
    "https://permitpro-ai.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for now to debug
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)

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
    return {"service": "PermitPro AI", "version": "1.3.0", "status": "running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


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
    if authorization and authorization.startswith("Bearer "):
        try:
            from auth import decode_access_token

            payload = decode_access_token(authorization[7:])
            user_id = int(payload.get("sub"))
        except:
            pass

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

Return JSON:
{{
    "summary": "brief summary",
    "overall_status": "READY|NEEDS_ATTENTION|INCOMPLETE",
    "compliance_score": 0-100,
    "critical_issues": ["issues"],
    "missing_documents": ["missing"],
    "recommendations": ["recommendations"]
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
    print("🚀 PermitPro AI v1.3.0 Started")
    print(f"   API Key: {'✅' if get_api_key() else '❌'}")
    print(f"   JWT Key: {'✅' if os.getenv('JWT_SECRET_KEY') else '❌'}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
