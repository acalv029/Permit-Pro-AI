from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import Form
import os
import tempfile
import shutil
import uuid
from datetime import datetime
from typing import Optional
import anthropic
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# TEST - print to see if API key is loaded
print("=" * 50)
print("API KEY TEST:")
api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("AI-PERMIT-KEY")
if api_key:
    print(f"✅ API Key found: {api_key[:20]}...")
else:
    print("❌ NO API KEY FOUND!")
print("=" * 50)

# Import your existing modules
from reader import get_document_text
from permit_data import get_permit_requirements, get_city_key, get_permit_types
from analyzer import analyze_document_with_claude

app = FastAPI(title="South Florida Permit Checker API")

# CORS - allows your frontend to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://permit-pro-ai.vercel.app",
        "https://south-florida-permit-helper-production.up.railway.app",
        "https://frontend-nine-mu-19.vercel.app",
        "https://south-florida-permit-helper.vercel.app",
        "*",  # Allow all origins for development
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (replace with database later)
analysis_results = {}


@app.get("/")
async def root():
    """Root endpoint with API key status"""
    api_key = (
        os.getenv("AI_PERMIT_KEY")
        or os.getenv("AI-PERMIT-KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )
    return {
        "message": "South Florida Permit Checker API",
        "status": "running",
        "api_key_configured": bool(api_key),
        "endpoints": {
            "health": "/health or /api/health",
            "cities": "/api/cities",
            "analyze": "/api/analyze-permit",
        },
    }


# ✅ NEW: Add /health endpoint (without /api prefix)
@app.get("/health")
async def health_check_simple():
    """Health check endpoint - simple version"""
    api_key = (
        os.getenv("AI_PERMIT_KEY")
        or os.getenv("AI-PERMIT-KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )
    return {
        "status": "healthy",
        "api_key_present": bool(api_key),
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "analyze_permit": "/api/analyze-permit (POST)",
            "cities": "/api/cities (GET)",
            "permits": "/api/permits/{city_key} (GET)",
        },
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint - API version"""
    api_key = (
        os.getenv("AI_PERMIT_KEY")
        or os.getenv("AI-PERMIT-KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )
    return {
        "status": "healthy",
        "api_key_present": bool(api_key),
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/cities")
async def get_cities():
    """
    Get list of available cities
    """
    cities = {
        "Fort Lauderdale": {
            "key": "fort_lauderdale",
            "county": "Broward County",
            "phone": "(954) 828-6520",
            "address": "700 NW 19th Ave, Fort Lauderdale, FL 33311",
        },
        "Pompano Beach": {
            "key": "pompano_beach",
            "county": "Broward County",
            "phone": "(954) 786-4600",
            "address": "100 W Atlantic Blvd, Pompano Beach, FL 33060",
        },
        "Lauderdale-by-the-Sea": {
            "key": "lauderdale_by_the_sea",
            "county": "Broward County",
            "phone": "(954) 640-4215",
            "address": "4501 N Ocean Dr, Lauderdale-by-the-Sea, FL 33308",
        },
        "Coral Springs": {
            "key": "coral_springs",
            "county": "Broward County",
            "phone": "(954) 344-1111",
            "address": "9551 W Sample Rd, Coral Springs, FL 33065",
        },
        "Hollywood": {
            "key": "hollywood",
            "county": "Broward County",
            "phone": "(954) 921-3201",
            "address": "2600 Hollywood Blvd, Hollywood, FL 33020",
        },
        "Boca Raton": {
            "key": "boca_raton",
            "county": "Palm Beach County",
            "phone": "(561) 393-7930",
            "address": "200 NW 2nd Ave, Boca Raton, FL 33432",
        },
    }
    return cities


@app.get("/api/permits/{city_key}")
async def get_city_permits(city_key: str):
    """
    Get available permit types for a specific city
    """
    try:
        permit_types = get_permit_types(city_key)
        return {"city_key": city_key, "permit_types": permit_types}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"City not found: {city_key}")


@app.post("/api/analyze-permit")
async def analyze_permit(
    file: UploadFile = File(...),
    city: str = Form(...),
    permit_type: str = Form(...),
):
    """
    Upload a permit document for analysis
    """
    print(f"📄 Received file: {file.filename}")
    print(f"🏙️  City: {city}")
    print(f"📋 Permit type: {permit_type}")

    # Validate file type
    allowed_types = [".pdf", ".png", ".jpg", ".jpeg"]
    file_ext = os.path.splitext(file.filename)[1].lower()

    if file_ext not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported. Please upload: {', '.join(allowed_types)}",
        )

    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())

    # Create temp file
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, f"upload{file_ext}")

    try:
        # Save uploaded file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        print(f"💾 File saved to: {temp_path}")

        # Extract text from document
        print("📖 Extracting text from document...")
        document_text = get_document_text(temp_path, is_blueprint=False)

        # Get permit requirements
        print(f"🔍 Getting requirements for {city} - {permit_type}")
        city_key = get_city_key(city)
        requirements = get_permit_requirements(city_key, permit_type)

        # Get API key
        api_key = (
            os.getenv("AI_PERMIT_KEY")
            or os.getenv("AI-PERMIT-KEY")
            or os.getenv("ANTHROPIC_API_KEY")
        )

        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="API key not configured. Please add ANTHROPIC_API_KEY to environment variables.",
            )

        # Analyze document
        print("🤖 Starting AI analysis...")
        analysis = analyze_document_with_claude(document_text, requirements, api_key)
        print("✅ Analysis complete!")

        # Store results
        analysis_results[analysis_id] = {
            "id": analysis_id,
            "filename": file.filename,
            "city": city,
            "permit_type": permit_type,
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis,
            "status": "completed",
        }

        # Cleanup temp files
        shutil.rmtree(temp_dir)

        return {
            "analysis_id": analysis_id,
            "status": "completed",
            "analysis": analysis,
            "city": city,
            "permit_type": requirements["name"],
        }

    except Exception as e:
        # Cleanup on error
        print(f"❌ Error: {str(e)}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """
    Retrieve analysis results by ID
    """
    if analysis_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return analysis_results[analysis_id]


@app.get("/api/pricing")
async def get_pricing():
    """
    Return subscription tiers
    """
    return {
        "tiers": [
            {
                "name": "Free",
                "price": 0,
                "features": [
                    "3 permit checks per month",
                    "Basic analysis",
                    "6 cities covered",
                    "Community support",
                ],
                "stripe_price_id": None,
            },
            {
                "name": "Contractor Pro",
                "price": 49,
                "features": [
                    "Unlimited permit checks",
                    "AI-powered analysis",
                    "All South Florida cities",
                    "Priority support",
                    "Save analysis history",
                    "Download PDF reports",
                ],
                "stripe_price_id": "price_xxx",
            },
            {
                "name": "Business",
                "price": 149,
                "features": [
                    "Everything in Pro",
                    "Team collaboration (5 users)",
                    "API access",
                    "White-label reports",
                    "Dedicated support",
                    "Training sessions",
                ],
                "stripe_price_id": "price_yyy",
            },
        ]
    }


# Authentication placeholders
@app.post("/api/auth/register")
async def register(email: str, password: str):
    """User registration"""
    # TODO: Implement with database and password hashing
    return {"message": "Registration endpoint - implement with database"}


@app.post("/api/auth/login")
async def login(email: str, password: str):
    """User login"""
    # TODO: Implement with JWT tokens
    return {"message": "Login endpoint - implement with JWT"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
