"""
PermitPro AI - South Florida Permit Checker API
Production-ready FastAPI backend with security hardening and user authentication
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
import os
import tempfile
import shutil
import uuid
import re
import magic
import json
from datetime import datetime
from typing import Optional, List
from dotenv import load_dotenv

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Database
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
    JSON as SQLAlchemyJSON,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import bcrypt

# Load environment variables
load_dotenv()

# Import modules
from reader import get_document_text
from permit_data import get_permit_requirements, get_city_key, get_permit_types
from analyzer import analyze_document_with_claude

# Auth imports
from auth import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    AnalysisHistoryItem,
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_id,
)

# ============================================================================
# DATABASE SETUP
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./permitpro.db")

# Handle PostgreSQL URL format from Railway/Heroku
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# DATABASE MODELS
# ============================================================================


class User(Base):
    """User model"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    company_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    subscription_tier = Column(String(50), default="free")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    analyses = relationship(
        "AnalysisHistory",
        back_populates="user",
        order_by="desc(AnalysisHistory.created_at)",
    )


class AnalysisHistory(Base):
    """Analysis history - stores past permit analyses"""

    __tablename__ = "analysis_history"

    id = Column(Integer, primary_key=True, index=True)
    analysis_uuid = Column(String(36), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Analysis metadata
    city = Column(String(100), nullable=False)
    permit_type = Column(String(100), nullable=False)
    files_analyzed = Column(Integer, default=0)
    total_size_bytes = Column(Integer)

    # Results
    overall_status = Column(String(50))
    compliance_score = Column(Integer)

    # Detailed data (stored as JSON text)
    file_list = Column(Text)  # JSON string
    analysis_data = Column(Text)  # JSON string

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    user = relationship("User", back_populates="analyses")


# Create tables
Base.metadata.create_all(bind=engine)
print("✅ Database tables initialized")


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

# IP Blocklist for known abuse
IP_BLOCKLIST = set(
    [
        # Add known abusive IPs here
        # "1.2.3.4",
        # "5.6.7.8",
    ]
)

# File upload limits
MAX_FILES_PER_UPLOAD = 50
MAX_FILE_SIZE_MB = 25
MAX_TOTAL_SIZE_MB = 200
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/jpg",
}
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}

# Rate limiting configuration
limiter = Limiter(key_func=get_remote_address)


# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        return response


class IPBlocklistMiddleware(BaseHTTPMiddleware):
    """Block requests from known abusive IPs"""

    async def dispatch(self, request: Request, call_next):
        # Get client IP (check X-Forwarded-For for proxy scenarios)
        client_ip = request.client.host if request.client else None
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            # Take the first IP in the chain (original client)
            client_ip = forwarded_for.split(",")[0].strip()

        if client_ip in IP_BLOCKLIST:
            print(f"🚫 BLOCKED: Request from blocklisted IP {client_ip}")
            return JSONResponse(status_code=403, content={"detail": "Access denied"})

        return await call_next(request)


# ============================================================================
# APP CONFIGURATION
# ============================================================================

app = FastAPI(
    title="PermitPro AI - South Florida Permit Checker",
    description="AI-powered permit analysis for South Florida municipalities",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add security middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(IPBlocklistMiddleware)

# CORS Configuration - Production Ready (NO wildcards)
ALLOWED_ORIGINS = [
    # Local development
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    # Production deployments
    "https://permit-pro-ai.vercel.app",
    "https://permitpro-ai.vercel.app",
    "https://south-florida-permit-helper.vercel.app",
    "https://frontend-nine-mu-19.vercel.app",
    # Railway backend (for health checks)
    "https://south-florida-permit-helper-production.up.railway.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",  # Allow Vercel preview deployments
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)

# In-memory storage (replace with database in production)
analysis_results = {}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def get_api_key() -> Optional[str]:
    """Get API key from environment variables with multiple fallbacks"""
    return (
        os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("AI_PERMIT_KEY")
        or os.getenv("AI-PERMIT-KEY")
    )


def get_valid_api_keys() -> set:
    """Get set of valid client API keys for authorization"""
    keys = set()
    # Primary API key
    primary_key = os.getenv("CLIENT_API_KEY")
    if primary_key:
        keys.add(primary_key)
    # Additional keys (comma-separated)
    additional_keys = os.getenv("ADDITIONAL_API_KEYS", "")
    if additional_keys:
        keys.update(k.strip() for k in additional_keys.split(",") if k.strip())
    return keys


def verify_authorization(authorization: Optional[str] = Header(None)) -> bool:
    """Verify the Authorization header contains a valid API key"""
    if not authorization:
        return False

    # Check for Bearer token format
    if not authorization.startswith("Bearer "):
        return False

    token = authorization[7:]  # Remove "Bearer " prefix
    valid_keys = get_valid_api_keys()

    # If no keys configured, allow all (development mode)
    if not valid_keys:
        return True

    return token in valid_keys


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove potentially dangerous characters"""
    # Remove path components
    filename = os.path.basename(filename)
    # Remove special characters, keep alphanumeric, dash, underscore, dot
    sanitized = re.sub(r"[^\w\-.]", "_", filename)
    # Prevent double dots (path traversal)
    sanitized = re.sub(r"\.{2,}", ".", sanitized)
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:250] + ext
    return sanitized


def validate_file_type(filename: str) -> tuple[bool, str]:
    """Validate uploaded file type by extension"""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return (
            False,
            f"File type '{ext}' not supported. Please upload: {', '.join(ALLOWED_EXTENSIONS)}",
        )
    return True, ext


def validate_mime_type(file_path: str) -> tuple[bool, str]:
    """Validate file MIME type server-side"""
    try:
        mime = magic.Magic(mime=True)
        detected_type = mime.from_file(file_path)
        if detected_type not in ALLOWED_MIME_TYPES:
            return False, f"Invalid file type detected: {detected_type}"
        return True, detected_type
    except Exception as e:
        return False, f"Could not verify file type: {str(e)}"


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================


@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Validate password length
    if len(user_data.password) < 8:
        raise HTTPException(
            status_code=400, detail="Password must be at least 8 characters"
        )

    # Create new user
    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        company_name=user_data.company_name,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create access token
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


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login and get access token"""
    # Find user by email
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Verify password
    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Check if user is active
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is disabled")

    # Create access token
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
# ANALYSIS HISTORY ENDPOINTS
# ============================================================================


@app.get("/api/history")
async def get_analysis_history(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    limit: int = 20,
    offset: int = 0,
):
    """Get user's analysis history"""
    analyses = (
        db.query(AnalysisHistory)
        .filter(AnalysisHistory.user_id == user_id)
        .order_by(AnalysisHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    total = db.query(AnalysisHistory).filter(AnalysisHistory.user_id == user_id).count()

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
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/history/{analysis_uuid}")
async def get_analysis_detail(
    analysis_uuid: str,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Get detailed analysis by UUID"""
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

    # Parse JSON fields
    file_list = json.loads(analysis.file_list) if analysis.file_list else []
    analysis_data = json.loads(analysis.analysis_data) if analysis.analysis_data else {}

    return {
        "id": analysis.id,
        "analysis_uuid": analysis.analysis_uuid,
        "city": analysis.city,
        "permit_type": analysis.permit_type,
        "files_analyzed": analysis.files_analyzed,
        "file_list": file_list,
        "total_size_bytes": analysis.total_size_bytes,
        "overall_status": analysis.overall_status,
        "compliance_score": analysis.compliance_score,
        "analysis": analysis_data,
        "created_at": analysis.created_at.isoformat(),
    }


def save_analysis_to_history(
    db: Session,
    user_id: int,
    analysis_uuid: str,
    city: str,
    permit_type: str,
    files_analyzed: int,
    file_list: list,
    total_size_bytes: int,
    analysis_data: dict,
):
    """Helper function to save analysis to history"""
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
    return history


# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint with API information"""
    api_key = get_api_key()
    return {
        "service": "PermitPro AI - South Florida Permit Checker",
        "version": "1.2.0",
        "status": "running",
        "api_key_configured": bool(api_key),
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "auth": "/api/auth/register, /api/auth/login, /api/auth/me",
            "history": "/api/history",
            "cities": "/api/cities",
            "permits": "/api/permits/{city_key}",
            "analyze": "/api/analyze-permit (POST)",
            "analyze_folder": "/api/analyze-permit-folder (POST)",
            "pricing": "/api/pricing",
        },
        "limits": {
            "max_files": MAX_FILES_PER_UPLOAD,
            "max_file_size_mb": MAX_FILE_SIZE_MB,
            "max_total_size_mb": MAX_TOTAL_SIZE_MB,
            "allowed_types": list(ALLOWED_EXTENSIONS),
        },
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    api_key = get_api_key()
    return {
        "status": "healthy",
        "api_key_present": bool(api_key),
        "timestamp": datetime.now().isoformat(),
        "version": "1.2.0",
    }


@app.get("/api/health")
async def api_health_check():
    """API health check endpoint"""
    api_key = get_api_key()
    return {
        "status": "healthy",
        "api_key_present": bool(api_key),
        "timestamp": datetime.now().isoformat(),
        "endpoints_available": True,
    }


# ============================================================================
# CITY & PERMIT ENDPOINTS
# ============================================================================


@app.get("/api/cities")
async def get_cities():
    """Get list of available cities with details"""
    cities = {
        "Fort Lauderdale": {
            "key": "fort_lauderdale",
            "county": "Broward County",
            "phone": "(954) 828-6520",
            "address": "700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "portal": "LauderBuild",
        },
        "Pompano Beach": {
            "key": "pompano_beach",
            "county": "Broward County",
            "phone": "(954) 786-4600",
            "address": "100 W Atlantic Blvd, Pompano Beach, FL 33060",
            "portal": "Online Portal",
        },
        "Hollywood": {
            "key": "hollywood",
            "county": "Broward County",
            "phone": "(954) 921-3201",
            "address": "2600 Hollywood Blvd, Hollywood, FL 33020",
            "portal": "ePermits",
        },
        "Coral Springs": {
            "key": "coral_springs",
            "county": "Broward County",
            "phone": "(954) 344-1111",
            "address": "9551 W Sample Rd, Coral Springs, FL 33065",
            "portal": "Online Portal",
        },
        "Boca Raton": {
            "key": "boca_raton",
            "county": "Palm Beach County",
            "phone": "(561) 393-7930",
            "address": "200 NW 2nd Ave, Boca Raton, FL 33432",
            "portal": "Boca eHub",
        },
        "Lauderdale-by-the-Sea": {
            "key": "lauderdale_by_the_sea",
            "county": "Broward County",
            "phone": "(954) 640-4215",
            "address": "4501 N Ocean Dr, Lauderdale-by-the-Sea, FL 33308",
            "portal": "CAP Government",
        },
    }
    return {"cities": cities, "total": len(cities)}


@app.get("/api/permits/{city_key}")
async def get_city_permits(city_key: str):
    """Get available permit types for a specific city"""
    try:
        permit_types = get_permit_types(city_key)

        # Format for frontend consumption
        formatted_permits = {}
        for key, value in permit_types.items():
            formatted_permits[key] = {
                "name": value.get("name", key.replace("_", " ").title()),
                "item_count": len(value.get("items", [])),
            }

        return {
            "city_key": city_key,
            "permit_types": formatted_permits,
            "total_types": len(formatted_permits),
        }
    except Exception as e:
        raise HTTPException(
            status_code=404, detail=f"City '{city_key}' not found or has no permit data"
        )


# ============================================================================
# SINGLE FILE ANALYSIS ENDPOINT (Legacy support)
# ============================================================================


@app.post("/api/analyze-permit")
@limiter.limit("10/minute;100/hour")
async def analyze_permit(
    request: Request,
    file: UploadFile = File(...),
    city: str = Form(...),
    permit_type: str = Form(...),
    authorization: Optional[str] = Header(None),
):
    """
    Upload and analyze a single permit document against city requirements.

    - **file**: PDF, PNG, or JPG document
    - **city**: City name (e.g., "Fort Lauderdale")
    - **permit_type**: Type of permit (e.g., "building", "electrical")
    """

    # Verify authorization
    if not verify_authorization(authorization):
        client_ip = request.client.host if request.client else "unknown"
        print(f"⚠️ UNAUTHORIZED: Request from {client_ip} with invalid/missing auth")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Please provide a valid Authorization header.",
        )

    # Log request
    print(f"📄 Received analysis request:")
    print(f"   File: {file.filename}")
    print(f"   City: {city}")
    print(f"   Permit Type: {permit_type}")

    # Validate file type
    is_valid, file_ext = validate_file_type(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=file_ext)

    # Check API key
    api_key = get_api_key()
    if not api_key:
        raise HTTPException(
            status_code=500, detail="API key not configured. Please contact support."
        )

    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())

    # Create temp directory for file processing
    temp_dir = tempfile.mkdtemp()
    safe_filename = sanitize_filename(file.filename)
    temp_path = os.path.join(temp_dir, safe_filename)

    try:
        # Save uploaded file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Check file size
        file_size = os.path.getsize(temp_path)
        if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail=f"File exceeds maximum size of {MAX_FILE_SIZE_MB}MB",
            )

        # Validate MIME type
        is_valid_mime, mime_result = validate_mime_type(temp_path)
        if not is_valid_mime:
            raise HTTPException(status_code=400, detail=mime_result)

        print(f"💾 File saved: {temp_path} ({format_file_size(file_size)})")

        # Extract text from document
        print("📖 Extracting text from document...")
        document_text = get_document_text(temp_path, is_blueprint=False)

        if not document_text or "Error" in document_text[:50]:
            raise HTTPException(
                status_code=400,
                detail="Could not extract text from document. Please ensure the file is readable.",
            )

        # Get city key and requirements
        print(f"📍 Getting requirements for {city} - {permit_type}")
        city_key = get_city_key(city)
        requirements = get_permit_requirements(city_key, permit_type)

        if not requirements or not requirements.get("items"):
            raise HTTPException(
                status_code=404,
                detail=f"No requirements found for {city} - {permit_type}",
            )

        # Analyze with Claude
        print("🤖 Starting AI analysis...")
        analysis = analyze_document_with_claude(document_text, requirements, api_key)
        print("✅ Analysis complete!")

        # Store results
        result = {
            "id": analysis_id,
            "filename": file.filename,
            "city": city,
            "city_key": city_key,
            "permit_type": permit_type,
            "permit_name": requirements["name"],
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis,
            "status": "completed",
            "requirements_checked": len(requirements.get("items", [])),
        }

        analysis_results[analysis_id] = result

        # Cleanup
        shutil.rmtree(temp_dir)

        return {
            "success": True,
            "analysis_id": analysis_id,
            "status": "completed",
            "analysis": analysis,
            "city": city,
            "permit_type": requirements["name"],
            "requirements_checked": len(requirements.get("items", [])),
        }

    except HTTPException:
        # Re-raise HTTP exceptions
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise

    except Exception as e:
        # Cleanup and log error
        print(f"❌ Error during analysis: {str(e)}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# MULTI-FILE FOLDER ANALYSIS ENDPOINT
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
    """
    Upload and analyze multiple permit documents (folder) against city requirements.
    If logged in (JWT token), saves analysis to history.

    - **files**: Multiple PDF, PNG, or JPG documents (max 50 files, 200MB total)
    - **city**: City name (e.g., "Fort Lauderdale")
    - **permit_type**: Type of permit (e.g., "building", "electrical")
    """

    # Try to get user from JWT token (optional - for history saving)
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            from auth import decode_access_token

            payload = decode_access_token(token)
            user_id = int(payload.get("sub"))
        except:
            pass  # Not a valid JWT, might be API key

    # Verify authorization (API key OR valid JWT)
    if not verify_authorization(authorization) and not user_id:
        client_ip = request.client.host if request.client else "unknown"
        print(
            f"⚠️ UNAUTHORIZED: Folder upload from {client_ip} with invalid/missing auth"
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Please provide a valid Authorization header.",
        )

    # Validate file count
    if len(files) > MAX_FILES_PER_UPLOAD:
        raise HTTPException(
            status_code=400,
            detail=f"Too many files. Maximum is {MAX_FILES_PER_UPLOAD} files per upload.",
        )

    if len(files) == 0:
        raise HTTPException(status_code=400, detail="No files provided.")

    # Log request
    print(f"📁 Received folder analysis request:")
    print(f"   Files: {len(files)}")
    print(f"   City: {city}")
    print(f"   Permit Type: {permit_type}")

    # Check API key
    api_key = get_api_key()
    if not api_key:
        raise HTTPException(
            status_code=500, detail="API key not configured. Please contact support."
        )

    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())

    # Create temp directory for file processing
    temp_dir = tempfile.mkdtemp()

    try:
        # Process all files
        processed_files = []
        total_size = 0
        invalid_files = []
        all_text_content = []

        for upload_file in files:
            # Validate file type
            is_valid, file_ext = validate_file_type(upload_file.filename)
            if not is_valid:
                invalid_files.append(f"{upload_file.filename}: {file_ext}")
                continue

            # Sanitize filename
            safe_filename = sanitize_filename(upload_file.filename)
            temp_path = os.path.join(
                temp_dir, f"{len(processed_files)}_{safe_filename}"
            )

            # Save file
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(upload_file.file, buffer)

            # Check individual file size
            file_size = os.path.getsize(temp_path)
            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                invalid_files.append(
                    f"{upload_file.filename}: exceeds {MAX_FILE_SIZE_MB}MB limit"
                )
                os.remove(temp_path)
                continue

            # Check total size
            total_size += file_size
            if total_size > MAX_TOTAL_SIZE_MB * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail=f"Total folder size exceeds {MAX_TOTAL_SIZE_MB}MB limit.",
                )

            # Validate MIME type
            is_valid_mime, mime_result = validate_mime_type(temp_path)
            if not is_valid_mime:
                invalid_files.append(f"{upload_file.filename}: {mime_result}")
                os.remove(temp_path)
                continue

            processed_files.append(
                {
                    "original_name": upload_file.filename,
                    "safe_name": safe_filename,
                    "path": temp_path,
                    "size": file_size,
                    "size_formatted": format_file_size(file_size),
                }
            )

        # Check if we have any valid files
        if not processed_files:
            raise HTTPException(
                status_code=400,
                detail=f"No valid files to process. Issues: {'; '.join(invalid_files)}",
            )

        print(
            f"📂 Processing {len(processed_files)} valid files ({format_file_size(total_size)} total)"
        )

        # Extract text from all files
        for i, file_info in enumerate(processed_files):
            print(
                f"📖 [{i + 1}/{len(processed_files)}] Extracting: {file_info['original_name']}"
            )

            try:
                text_content = get_document_text(file_info["path"], is_blueprint=False)
                if text_content and "Error" not in text_content[:50]:
                    all_text_content.append(
                        f"\n{'=' * 60}\n"
                        f"FILE: {file_info['original_name']} ({file_info['size_formatted']})\n"
                        f"{'=' * 60}\n"
                        f"{text_content}"
                    )
                else:
                    all_text_content.append(
                        f"\n{'=' * 60}\n"
                        f"FILE: {file_info['original_name']} ({file_info['size_formatted']})\n"
                        f"{'=' * 60}\n"
                        f"[Unable to extract text - may be scanned image]"
                    )
            except Exception as e:
                all_text_content.append(
                    f"\n{'=' * 60}\n"
                    f"FILE: {file_info['original_name']} ({file_info['size_formatted']})\n"
                    f"{'=' * 60}\n"
                    f"[Error reading file: {str(e)}]"
                )

        # Combine all text
        combined_text = "\n".join(all_text_content)

        # Get city key and requirements
        print(f"📍 Getting requirements for {city} - {permit_type}")
        city_key = get_city_key(city)
        requirements = get_permit_requirements(city_key, permit_type)

        if not requirements or not requirements.get("items"):
            raise HTTPException(
                status_code=404,
                detail=f"No requirements found for {city} - {permit_type}",
            )

        # Build file list for prompt
        file_list_str = "\n".join(
            [
                f"  • {f['original_name']} ({f['size_formatted']})"
                for f in processed_files
            ]
        )

        # Create enhanced analysis prompt for multi-file
        enhanced_requirements = {
            "name": requirements["name"],
            "items": requirements["items"],
            "_multi_file_context": {
                "total_files": len(processed_files),
                "file_list": file_list_str,
                "total_size": format_file_size(total_size),
                "instruction": """
IMPORTANT: You are analyzing a COMPLETE PERMIT PACKAGE containing multiple files.
- Review ALL documents together as a cohesive submission
- Identify documents that fulfill requirements across the entire package
- Consolidate duplicate findings (e.g., "Found in 3 files: missing engineer stamp")
- Focus on: critical issues, compliance gaps, missing documents, action items
- Be concise - use structured bullet points, avoid verbose explanations
- Note any documents that appear to be missing from the package
- Provide a unified recommendation for the entire submission
""",
            },
        }

        # Analyze with Claude
        print("🤖 Starting comprehensive AI analysis...")
        analysis = analyze_folder_with_claude(
            combined_text, enhanced_requirements, api_key, len(processed_files)
        )
        print("✅ Analysis complete!")

        # Build file tree for response
        file_tree = [
            {"name": f["original_name"], "size": f["size_formatted"]}
            for f in processed_files
        ]

        # Store results
        result = {
            "id": analysis_id,
            "files_analyzed": len(processed_files),
            "file_tree": file_tree,
            "total_size": format_file_size(total_size),
            "invalid_files": invalid_files if invalid_files else None,
            "city": city,
            "city_key": city_key,
            "permit_type": permit_type,
            "permit_name": requirements["name"],
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis,
            "status": "completed",
            "requirements_checked": len(requirements.get("items", [])),
        }

        analysis_results[analysis_id] = result

        # Save to history if user is logged in
        if user_id:
            try:
                save_analysis_to_history(
                    db=db,
                    user_id=user_id,
                    analysis_uuid=analysis_id,
                    city=city,
                    permit_type=requirements["name"],
                    files_analyzed=len(processed_files),
                    file_list=file_tree,
                    total_size_bytes=total_size,
                    analysis_data=analysis,
                )
                print(f"💾 Analysis saved to history for user {user_id}")
            except Exception as e:
                print(f"⚠️ Failed to save to history: {str(e)}")

        # Cleanup
        shutil.rmtree(temp_dir)

        return {
            "success": True,
            "analysis_id": analysis_id,
            "status": "completed",
            "files_analyzed": len(processed_files),
            "file_tree": file_tree,
            "total_size": format_file_size(total_size),
            "invalid_files": invalid_files if invalid_files else None,
            "analysis": analysis,
            "city": city,
            "permit_type": requirements["name"],
            "requirements_checked": len(requirements.get("items", [])),
        }

    except HTTPException:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise

    except Exception as e:
        print(f"❌ Error during folder analysis: {str(e)}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Folder analysis failed: {str(e)}")


def analyze_folder_with_claude(
    combined_text: str,
    requirements: dict,
    api_key: str,
    file_count: int,
    model: str = "claude-sonnet-4-20250514",
) -> dict:
    """
    Analyze combined permit documents with token-efficient prompting.
    """
    import anthropic
    import json
    import re

    client = anthropic.Anthropic(api_key=api_key)

    # Build requirements list
    requirements_list = "\n".join(
        [f"  {i + 1}. {item}" for i, item in enumerate(requirements.get("items", []))]
    )

    permit_name = requirements.get("name", "Building Permit")
    multi_file_context = requirements.get("_multi_file_context", {})

    # Token-efficient system prompt
    system_prompt = """You are PermitPro AI, an expert permit analyst for South Florida.
Analyze permit packages efficiently. Be CONCISE - use bullet points, avoid verbose explanations.
Consolidate duplicate findings across files. Focus on actionable insights.
Always respond with structured JSON."""

    # Truncate combined text to avoid token waste (keep under 60K tokens ~ 240K chars)
    max_chars = 200000
    if len(combined_text) > max_chars:
        combined_text = (
            combined_text[:max_chars]
            + "\n\n[... Document truncated for efficiency ...]"
        )

    user_prompt = f"""Analyze this COMPLETE PERMIT PACKAGE ({file_count} files) for {permit_name}.

FILES IN PACKAGE:
{multi_file_context.get("file_list", "Multiple files")}
Total Size: {multi_file_context.get("total_size", "Unknown")}

REQUIREMENTS TO CHECK:
{requirements_list}

COMBINED DOCUMENT CONTENT:
---
{combined_text}
---

Provide CONCISE JSON response:
{{
    "summary": "2-3 sentence executive summary",
    "overall_status": "READY" | "NEEDS_ATTENTION" | "INCOMPLETE",
    "compliance_score": <0-100>,
    "items_found": [
        {{"requirement": "text", "status": "FOUND|MISSING|PARTIAL", "files": ["which files"], "note": "brief note"}}
    ],
    "critical_issues": ["Concise critical items - consolidate duplicates"],
    "missing_documents": ["List of typically required docs not found in package"],
    "recommendations": ["Top 3-5 actionable improvements"],
    "next_steps": ["Ordered action items"]
}}

Be concise. Consolidate findings. Focus on what's missing or needs attention."""

    try:
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
        )

        response_text = message.content[0].text

        # Parse JSON response
        json_patterns = [
            r"```json\s*([\s\S]*?)\s*```",
            r"```\s*([\s\S]*?)\s*```",
            r"\{[\s\S]*\}",
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, response_text)
            for match in matches:
                try:
                    json_str = match.strip()
                    if not json_str.startswith("{"):
                        continue
                    parsed = json.loads(json_str)
                    if isinstance(parsed, dict) and any(
                        key in parsed
                        for key in ["summary", "overall_status", "items_found"]
                    ):
                        parsed["_metadata"] = {
                            "model": model,
                            "files_analyzed": file_count,
                            "tokens_used": {
                                "input": message.usage.input_tokens,
                                "output": message.usage.output_tokens,
                            },
                        }
                        return parsed
                except json.JSONDecodeError:
                    continue

        # Fallback
        return {
            "summary": response_text[:500],
            "overall_status": "NEEDS_REVIEW",
            "compliance_score": 50,
            "items_found": [],
            "critical_issues": ["Unable to parse structured analysis"],
            "recommendations": ["Manual review recommended"],
            "next_steps": ["Contact support if issue persists"],
            "_raw_response": response_text[:2000],
        }

    except Exception as e:
        return {"error": "Analysis Error", "message": str(e), "overall_status": "ERROR"}


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Retrieve stored analysis results by ID"""
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis_results[analysis_id]


# ============================================================================
# PRICING ENDPOINT
# ============================================================================


@app.get("/api/pricing")
async def get_pricing():
    """Return subscription pricing tiers"""
    return {
        "currency": "USD",
        "tiers": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "period": "month",
                "features": [
                    "3 permit checks per month",
                    "Basic AI analysis",
                    "6 cities covered",
                    "Email support",
                ],
                "cta": "Get Started Free",
                "popular": False,
            },
            {
                "id": "pro",
                "name": "Contractor Pro",
                "price": 49,
                "period": "month",
                "features": [
                    "Unlimited permit checks",
                    "Advanced AI analysis",
                    "All South Florida cities",
                    "Priority support",
                    "Analysis history",
                    "PDF report downloads",
                    "Multi-file folder upload (200MB)",
                ],
                "cta": "Start Pro Trial",
                "popular": True,
            },
            {
                "id": "business",
                "name": "Business",
                "price": 149,
                "period": "month",
                "features": [
                    "Everything in Pro",
                    "Team collaboration (5 users)",
                    "API access",
                    "White-label reports",
                    "Dedicated support",
                    "Custom training",
                ],
                "cta": "Contact Sales",
                "popular": False,
            },
        ],
    }


# ============================================================================
# UPLOAD LIMITS ENDPOINT (for frontend)
# ============================================================================


@app.get("/api/upload-limits")
async def get_upload_limits():
    """Return file upload limits for frontend validation"""
    return {
        "max_files": MAX_FILES_PER_UPLOAD,
        "max_file_size_mb": MAX_FILE_SIZE_MB,
        "max_total_size_mb": MAX_TOTAL_SIZE_MB,
        "allowed_extensions": list(ALLOWED_EXTENSIONS),
        "allowed_mime_types": list(ALLOWED_MIME_TYPES),
    }


# ============================================================================
# STARTUP
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    api_key = get_api_key()
    print("=" * 60)
    print("🚀 PermitPro AI v1.1.0 - Starting Up")
    print("=" * 60)
    print(f"✅ API Key Configured: {bool(api_key)}")
    if api_key:
        print(f"   Key prefix: {api_key[:15]}...")
    print(f"✅ CORS Origins: {len(ALLOWED_ORIGINS)} configured")
    print(f"✅ Rate Limiting: 10/min, 100/hour per IP")
    print(f"✅ Upload Limits: {MAX_FILES_PER_UPLOAD} files, {MAX_TOTAL_SIZE_MB}MB max")
    print(f"✅ Security Headers: Enabled")
    print(f"✅ Documentation: /docs")
    print("=" * 60)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
