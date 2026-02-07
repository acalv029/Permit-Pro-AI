"""
PermitPro AI - Document Analyzer Module (Cost-Optimized)
Multi-provider AI analysis: Gemini Flash (default) + Claude Sonnet (premium)
"""

import anthropic
import json
import re
import os
from typing import Optional


# ============================================================================
# COST TRACKING (estimated costs per 1K tokens)
# ============================================================================
COST_PER_1K = {
    "gemini-2.0-flash": {"input": 0.0000750, "output": 0.000300},
    "gemini-2.0-flash-lite": {"input": 0.0000000, "output": 0.000000},  # Free tier
    "claude-sonnet-4-20250514": {"input": 0.003000, "output": 0.015000},
    "claude-haiku-3-20240307": {"input": 0.000250, "output": 0.001250},
}


# ============================================================================
# SMART DOCUMENT TRIMMING
# ============================================================================


def trim_document_smart(document_text: str, max_chars: int = 8000) -> str:
    """
    Intelligently trim document text to reduce token usage.
    Keeps the most permit-relevant sections instead of blindly truncating.

    For a typical permit doc, the key info is in headers, first pages,
    and sections mentioning permits, contractors, owners, etc.
    """
    if len(document_text) <= max_chars:
        return document_text

    # Priority keywords for permit documents
    priority_keywords = [
        "permit",
        "application",
        "owner",
        "contractor",
        "license",
        "address",
        "property",
        "description",
        "project",
        "scope",
        "insurance",
        "commencement",
        "notice",
        "noc",
        "sealed",
        "plans",
        "drawings",
        "engineer",
        "architect",
        "inspection",
        "zoning",
        "flood",
        "energy",
        "hoa",
        "approval",
        "fee",
        "value",
        "estimated",
        "square",
        "feet",
        "electrical",
        "plumbing",
        "mechanical",
        "roofing",
        "building",
    ]

    lines = document_text.split("\n")
    scored_lines = []

    for i, line in enumerate(lines):
        score = 0
        line_lower = line.lower().strip()

        # Boost first 30 lines (header/summary area)
        if i < 30:
            score += 3

        # Boost lines with priority keywords
        for kw in priority_keywords:
            if kw in line_lower:
                score += 2

        # Boost lines that look like form fields (contain ":" or are short labels)
        if ":" in line and len(line) < 200:
            score += 2

        # Boost lines with numbers (addresses, values, dates)
        if any(c.isdigit() for c in line):
            score += 1

        # Skip empty or very short lines
        if len(line_lower) < 3:
            score = 0

        scored_lines.append((score, i, line))

    # Sort by score (descending), keep top lines, then re-sort by position
    scored_lines.sort(key=lambda x: x[0], reverse=True)

    kept_lines = []
    char_count = 0
    selected = []

    for score, idx, line in scored_lines:
        if char_count + len(line) > max_chars:
            break
        selected.append((idx, line))
        char_count += len(line) + 1

    # Re-sort by original position to maintain document order
    selected.sort(key=lambda x: x[0])

    trimmed = "\n".join(line for _, line in selected)

    if len(trimmed) < len(document_text):
        trimmed += f"\n\n[Document trimmed from {len(document_text)} to {len(trimmed)} chars for analysis]"

    return trimmed


# ============================================================================
# GEMINI FLASH PROVIDER (Default - Low Cost)
# ============================================================================


def analyze_with_gemini(
    document_text: str,
    requirements: dict,
    api_key: str,
    model: str = "gemini-2.0-flash",
) -> dict:
    """
    Analyze permit document using Google Gemini Flash.
    ~90% cheaper than Claude Sonnet for structured analysis tasks.

    Cost: ~$0.001-$0.01 per analysis vs $0.05-$0.15 for Sonnet
    """
    try:
        import google.generativeai as genai
    except ImportError:
        return {
            "error": "Provider Error",
            "message": "google-generativeai package not installed. Run: pip install google-generativeai",
            "overall_status": "ERROR",
        }

    genai.configure(api_key=api_key)

    # Trim document to save tokens
    trimmed_text = trim_document_smart(document_text, max_chars=8000)

    requirements_list = "\n".join(
        [f"  {i + 1}. {item}" for i, item in enumerate(requirements.get("items", []))]
    )

    permit_name = requirements.get("name", "Building Permit")

    prompt = f"""You are PermitPro AI, an expert permit analyst for South Florida building permits.
Analyze this permit document against requirements for a {permit_name}.

REQUIREMENTS TO CHECK:
{requirements_list}

DOCUMENT CONTENT:
---
{trimmed_text}
---

Respond with ONLY valid JSON (no markdown, no backticks) using this exact structure:
{{
    "summary": "Brief 2-3 sentence executive summary",
    "overall_status": "READY" or "NEEDS_ATTENTION" or "INCOMPLETE",
    "compliance_score": <number 0-100>,
    "items_found": [
        {{
            "requirement": "The requirement text",
            "status": "FOUND" or "MISSING" or "PARTIAL" or "UNCLEAR",
            "evidence": "Where/how this was found (if applicable)",
            "recommendation": "Action needed (if not FOUND)"
        }}
    ],
    "critical_issues": ["List of must-fix items"],
    "recommendations": ["List of improvements"],
    "next_steps": ["Ordered actions to take"]
}}

Be specific. Quote relevant sections when possible."""

    try:
        gen_model = genai.GenerativeModel(model)
        response = gen_model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=3000,
                temperature=0.1,  # Low temp for consistent structured output
            ),
        )

        response_text = response.text
        analysis = parse_analysis_response(response_text)

        # Estimate token usage (rough: 4 chars ≈ 1 token)
        est_input_tokens = len(prompt) // 4
        est_output_tokens = len(response_text) // 4

        analysis["_metadata"] = {
            "model": model,
            "provider": "google",
            "tier": "standard",
            "permit_type": permit_name,
            "requirements_checked": len(requirements.get("items", [])),
            "document_length": len(document_text),
            "trimmed_length": len(trimmed_text),
            "tokens_used": {"input": est_input_tokens, "output": est_output_tokens},
            "estimated_cost_usd": round(
                (est_input_tokens / 1000 * COST_PER_1K[model]["input"])
                + (est_output_tokens / 1000 * COST_PER_1K[model]["output"]),
                6,
            ),
        }

        return analysis

    except Exception as e:
        return {
            "error": "Gemini API Error",
            "message": f"Analysis failed: {str(e)}",
            "overall_status": "ERROR",
        }


# ============================================================================
# CLAUDE PROVIDER (Premium Tier)
# ============================================================================


def analyze_with_claude(
    document_text: str,
    requirements: dict,
    api_key: str,
    model: str = "claude-sonnet-4-20250514",
) -> dict:
    """
    Analyze permit document using Claude Sonnet (premium tier).
    Higher quality analysis for paying customers.
    """
    client = anthropic.Anthropic(api_key=api_key)

    # Still trim, but allow more content for premium
    trimmed_text = trim_document_smart(document_text, max_chars=12000)

    requirements_list = "\n".join(
        [f"  {i + 1}. {item}" for i, item in enumerate(requirements.get("items", []))]
    )

    permit_name = requirements.get("name", "Building Permit")

    system_prompt = """You are PermitPro AI, an expert permit analyst for South Florida building permits. 
Your job is to analyze permit documents and check them against municipal requirements.
You are thorough, accurate, and helpful. You identify both issues AND positive aspects.
You provide specific, actionable recommendations when items are missing or incomplete.
Always respond with structured JSON output only - no markdown fences."""

    user_prompt = f"""Analyze this permit document against the requirements for a {permit_name}.

REQUIREMENTS TO CHECK:
{requirements_list}

DOCUMENT CONTENT:
---
{trimmed_text}
---

Provide a JSON response with this exact structure:
{{
    "summary": "Brief 2-3 sentence executive summary of the analysis",
    "overall_status": "READY" | "NEEDS_ATTENTION" | "INCOMPLETE",
    "compliance_score": <number 0-100>,
    "items_found": [
        {{
            "requirement": "The requirement text",
            "status": "FOUND" | "MISSING" | "PARTIAL" | "UNCLEAR",
            "evidence": "Quote or description of where this was found (if applicable)",
            "recommendation": "Specific action needed (if not FOUND)"
        }}
    ],
    "critical_issues": ["List of critical items that MUST be addressed"],
    "recommendations": ["List of recommended improvements"],
    "next_steps": ["Ordered list of what to do next"]
}}

Be specific about what you found and what's missing. Quote relevant sections when possible."""

    try:
        message = client.messages.create(
            model=model,
            max_tokens=3500,
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
        )

        response_text = message.content[0].text
        analysis = parse_analysis_response(response_text)

        input_cost = (
            message.usage.input_tokens
            / 1000
            * COST_PER_1K.get(model, {}).get("input", 0.003)
        )
        output_cost = (
            message.usage.output_tokens
            / 1000
            * COST_PER_1K.get(model, {}).get("output", 0.015)
        )

        analysis["_metadata"] = {
            "model": model,
            "provider": "anthropic",
            "tier": "premium",
            "permit_type": permit_name,
            "requirements_checked": len(requirements.get("items", [])),
            "document_length": len(document_text),
            "trimmed_length": len(trimmed_text),
            "tokens_used": {
                "input": message.usage.input_tokens,
                "output": message.usage.output_tokens,
            },
            "estimated_cost_usd": round(input_cost + output_cost, 6),
        }

        return analysis

    except anthropic.APIConnectionError as e:
        return {
            "error": "Connection Error",
            "message": f"Could not connect to AI service: {str(e)}",
            "overall_status": "ERROR",
        }
    except anthropic.RateLimitError:
        return {
            "error": "Rate Limit",
            "message": "Too many requests. Please try again in a moment.",
            "overall_status": "ERROR",
        }
    except anthropic.APIStatusError as e:
        return {
            "error": "API Error",
            "message": f"AI service error: {str(e)}",
            "overall_status": "ERROR",
        }
    except Exception as e:
        return {
            "error": "Analysis Error",
            "message": f"Failed to analyze document: {str(e)}",
            "overall_status": "ERROR",
        }


# ============================================================================
# MAIN ENTRY POINT - SMART ROUTING
# ============================================================================


def analyze_document(
    document_text: str,
    requirements: dict,
    tier: str = "standard",
    anthropic_api_key: Optional[str] = None,
    google_api_key: Optional[str] = None,
) -> dict:
    """
    Main analysis function with smart provider routing.

    Tiers:
        "standard" → Gemini Flash (cheap, fast, good for checklist tasks)
        "premium"  → Claude Sonnet (best quality, for paid plans)

    Fallback: If preferred provider fails, falls back to the other.
    """

    if tier == "premium" and anthropic_api_key:
        # Premium tier: Claude Sonnet
        result = analyze_with_claude(document_text, requirements, anthropic_api_key)
        if result.get("overall_status") != "ERROR":
            return result
        # Fallback to Gemini if Claude fails
        if google_api_key:
            print("⚠️ Claude failed, falling back to Gemini Flash")
            return analyze_with_gemini(document_text, requirements, google_api_key)
        return result

    elif google_api_key:
        # Standard tier: Gemini Flash
        result = analyze_with_gemini(document_text, requirements, google_api_key)
        if result.get("overall_status") != "ERROR":
            return result
        # Fallback to Claude if Gemini fails
        if anthropic_api_key:
            print("⚠️ Gemini failed, falling back to Claude Sonnet")
            return analyze_with_claude(document_text, requirements, anthropic_api_key)
        return result

    elif anthropic_api_key:
        # No Google key, use Claude for everything
        return analyze_with_claude(document_text, requirements, anthropic_api_key)

    else:
        return {
            "error": "No API Key",
            "message": "No AI provider API key configured. Set GOOGLE_API_KEY or ANTHROPIC_API_KEY.",
            "overall_status": "ERROR",
        }


# ============================================================================
# QUICK CHECK (Uses Haiku - cheapest option)
# ============================================================================


def quick_check(
    document_text: str,
    anthropic_api_key: Optional[str] = None,
    google_api_key: Optional[str] = None,
) -> dict:
    """
    Quick check if a document is a valid permit document.
    Uses the cheapest available provider.
    """

    snippet = document_text[:2000]

    prompt = f"""Look at this document text and quickly assess:
1. Is this a permit-related document?
2. What type of permit does it appear to be?
3. What city/jurisdiction (if identifiable)?

Document (first 2000 chars):
{snippet}

Respond with ONLY valid JSON: {{"is_permit_document": true/false, "permit_type": "string", "jurisdiction": "string", "confidence": 0.0-1.0}}"""

    # Prefer Gemini Flash (cheapest) → Haiku → Sonnet
    if google_api_key:
        try:
            import google.generativeai as genai

            genai.configure(api_key=google_api_key)
            gen_model = genai.GenerativeModel("gemini-2.0-flash")
            response = gen_model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=200, temperature=0.0
                ),
            )
            return parse_analysis_response(response.text)
        except Exception:
            pass  # Fall through to Haiku

    if anthropic_api_key:
        try:
            client = anthropic.Anthropic(api_key=anthropic_api_key)
            message = client.messages.create(
                model="claude-haiku-3-20240307",  # Cheapest Claude model
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return parse_analysis_response(message.content[0].text)
        except Exception as e:
            pass

    # Default: assume it's a permit doc and proceed
    return {
        "is_permit_document": True,
        "permit_type": "unknown",
        "jurisdiction": "unknown",
        "confidence": 0.5,
    }


# ============================================================================
# BACKWARD COMPATIBILITY WRAPPER
# ============================================================================


def analyze_document_with_claude(
    document_text: str,
    requirements: dict,
    api_key: str,
    model: str = "claude-sonnet-4-20250514",
) -> dict:
    """
    Backward-compatible wrapper. Routes through the smart analyzer.
    Existing code calling this function will still work.
    """
    google_key = os.getenv("GOOGLE_API_KEY")

    # If Google key is available, use standard (cheap) tier by default
    if google_key:
        return analyze_document(
            document_text,
            requirements,
            tier="standard",
            anthropic_api_key=api_key,
            google_api_key=google_key,
        )

    # Otherwise fall back to Claude
    return analyze_with_claude(document_text, requirements, api_key, model)


# ============================================================================
# JSON PARSER (unchanged)
# ============================================================================


def parse_analysis_response(response_text: str) -> dict:
    """Parse JSON response from any AI provider."""
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
                    for key in [
                        "summary",
                        "overall_status",
                        "items_found",
                        "is_permit_document",
                    ]
                ):
                    return parsed
            except json.JSONDecodeError:
                continue

    return {
        "summary": response_text[:500] if len(response_text) > 500 else response_text,
        "overall_status": "NEEDS_REVIEW",
        "compliance_score": 50,
        "items_found": [],
        "critical_issues": [
            "Unable to parse structured analysis - manual review recommended"
        ],
        "recommendations": ["Please review the raw analysis output"],
        "next_steps": ["Contact support if this issue persists"],
        "_raw_response": response_text,
    }


# ============================================================================
# CLI TESTING
# ============================================================================

if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    google_key = os.getenv("GOOGLE_API_KEY")

    if not anthropic_key and not google_key:
        print("Error: Set ANTHROPIC_API_KEY or GOOGLE_API_KEY")
        exit(1)

    test_document = """
    BUILDING PERMIT APPLICATION
    City of Fort Lauderdale
    Property Address: 123 Ocean Drive, Fort Lauderdale, FL 33301
    Owner: John Smith
    Contractor: ABC Construction LLC - License #CGC123456
    Project Description: Kitchen remodel including new cabinets, countertops,
    and electrical upgrades for new appliances.
    Estimated Value: $45,000
    Attachments:
    - Site plan (2 copies)
    - Electrical drawings
    - Notice of Commencement
    """

    test_requirements = {
        "name": "Building Permit",
        "items": [
            "Two (2) sets of plans signed and sealed by a Florida licensed professional",
            "Completed permit application signed by owner or authorized agent",
            "Notice of Commencement (NOC) recorded with Broward County",
            "Contractor must be registered with City of Fort Lauderdale",
            "Proof of workers' compensation insurance or exemption",
        ],
    }

    # Test standard tier (Gemini Flash)
    print("=" * 50)
    print("Testing STANDARD tier (Gemini Flash)...")
    print("=" * 50)
    result = analyze_document(
        test_document,
        test_requirements,
        tier="standard",
        anthropic_api_key=anthropic_key,
        google_api_key=google_key,
    )
    print(json.dumps(result, indent=2))

    # Test premium tier (Claude Sonnet)
    print("\n" + "=" * 50)
    print("Testing PREMIUM tier (Claude Sonnet)...")
    print("=" * 50)
    result = analyze_document(
        test_document,
        test_requirements,
        tier="premium",
        anthropic_api_key=anthropic_key,
        google_api_key=google_key,
    )
    print(json.dumps(result, indent=2))
