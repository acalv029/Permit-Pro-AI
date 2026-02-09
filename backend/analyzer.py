"""
PermitPro AI - Document Analyzer Module (Enhanced)
Multi-provider AI analysis: Gemini Flash (default) + Claude Sonnet (premium)

Key improvements over v1:
    - Injects city-specific gotchas and rejection reasons into AI prompt
    - City info (NOC thresholds, portals, submission rules) included
    - Much stronger system prompt with domain expertise
    - Higher token limits to avoid truncating real permit packages
    - Smart document trimming preserves permit-critical content
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
    "gemini-2.0-flash-lite": {"input": 0.0000000, "output": 0.000000},
    "claude-sonnet-4-20250514": {"input": 0.003000, "output": 0.015000},
    "claude-haiku-3-20240307": {"input": 0.000250, "output": 0.001250},
}


# ============================================================================
# CITY CONTEXT BUILDER
# ============================================================================


def build_city_context(requirements: dict) -> str:
    """
    Build a rich city-specific context block from the requirements dict.
    This is the KEY improvement - permit_data.py has all this info,
    but the old analyzer never passed it to the AI.
    """
    parts = []

    city = requirements.get("city", "Unknown")
    city_info = requirements.get("city_info", {})
    gotchas = requirements.get("gotchas", [])

    # City header
    parts.append(f"CITY: {city}")

    # Key city facts the AI needs
    if city_info:
        if city_info.get("submission"):
            parts.append(f"SUBMISSION RULES: {city_info['submission']}")
        if city_info.get("portal"):
            parts.append(f"PORTAL: {city_info['portal']}")
        if city_info.get("noc_threshold"):
            noc_line = f"NOC THRESHOLD: ${city_info['noc_threshold']:,} general"
            if city_info.get("noc_threshold_roofing"):
                noc_line += f", ${city_info['noc_threshold_roofing']:,} roofing"
            if city_info.get("noc_threshold_hvac"):
                noc_line += f", ${city_info['noc_threshold_hvac']:,} HVAC"
            parts.append(noc_line)
        if city_info.get("plan_sets"):
            parts.append(f"PLAN SETS REQUIRED: {city_info['plan_sets']}")
        if city_info.get("insurance_holder"):
            parts.append(
                f"INSURANCE CERTIFICATE HOLDER MUST READ: '{city_info['insurance_holder']}'"
            )
        if city_info.get("hvhz"):
            parts.append(
                "HVHZ: Yes - Miami-Dade NOA or FL Product Approval required for ALL exterior products"
            )
        if city_info.get("fire_review_required"):
            parts.append(f"FIRE REVIEW: {city_info['fire_review_required']}")
        if city_info.get("no_owner_builder"):
            trades = ", ".join(city_info["no_owner_builder"])
            parts.append(f"NO OWNER-BUILDER ALLOWED FOR: {trades}")
        if city_info.get("survey_max_age"):
            parts.append(f"SURVEY MAX AGE: {city_info['survey_max_age']}")
        if city_info.get("notarization_required"):
            parts.append("NOTARIZATION: All applications MUST be notarized")

    # Known gotchas - these are the #1 rejection reasons per city
    if gotchas:
        parts.append("")
        parts.append(
            f"KNOWN REJECTION REASONS FOR {city.upper()} (check ALL of these):"
        )
        for i, gotcha in enumerate(gotchas, 1):
            parts.append(f"  {i}. {gotcha}")

    return "\n".join(parts)


# ============================================================================
# EXPERT SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = """You are PermitPro AI, an expert South Florida building permit analyst with deep knowledge of Broward County, Palm Beach County, and Miami-Dade County building departments.

YOUR EXPERTISE:
- You know that EVERY city has different quirks: ink color requirements, notarization rules, NOC thresholds, and submission portals.
- You know that the #1 cause of permit rejection is paperwork issues (missing signatures, wrong ink, missing NOC, expired surveys), NOT code violations.
- You know HVHZ (High Velocity Hurricane Zone) covers most of Broward and all of Miami-Dade, requiring Miami-Dade NOAs for exterior products.
- You know contractors constantly get burned by city-specific gotchas they didn't know about.

YOUR JOB:
1. Check every required document against what was actually uploaded
2. Flag city-specific gotchas that apply to THIS permit package
3. Identify missing, expired, or incomplete items
4. Provide specific, actionable fixes — not vague suggestions
5. Be the contractor's best friend who saves them from rejection

ANALYSIS RULES:
- If a document is mentioned but you can't verify its contents (e.g., "NOC attached"), mark it PARTIAL and note you couldn't verify the details
- If a required document appears completely absent from the uploaded materials, mark it MISSING
- If something looks present and correct, mark it FOUND with evidence
- If text is unclear or partially readable, mark it UNCLEAR and explain what you could/couldn't read
- Pay special attention to: dates (expired surveys, expired NOCs), dollar amounts (NOC thresholds), signatures, ink color mentions, and insurance certificate holders
- ALWAYS check if the project value triggers NOC requirements based on the city's threshold

RESPOND WITH ONLY VALID JSON. No markdown fences, no backticks, no explanation outside the JSON."""


# ============================================================================
# SMART DOCUMENT TRIMMING
# ============================================================================


def trim_document_smart(document_text: str, max_chars: int = 15000) -> str:
    """
    Intelligently trim document text to reduce token usage.
    Keeps the most permit-relevant sections instead of blindly truncating.
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
        "notari",
        "survey",
        "elevation",
        "wind",
        "product approval",
        "noa",
        "signature",
        "ink",
        "expire",
        "date",
        "certificate",
    ]

    lines = document_text.split("\n")
    scored_lines = []

    for i, line in enumerate(lines):
        score = 0
        line_lower = line.lower().strip()

        # Boost first 40 lines (header/summary area)
        if i < 40:
            score += 3

        # Boost lines with priority keywords
        for kw in priority_keywords:
            if kw in line_lower:
                score += 2

        # Boost lines that look like form fields
        if ":" in line and len(line) < 200:
            score += 2

        # Boost lines with numbers (addresses, values, dates)
        if any(c.isdigit() for c in line):
            score += 1

        # Boost page headers (our reader adds these)
        if line.startswith("--- Page"):
            score += 3

        # Skip empty or very short lines
        if len(line_lower) < 3:
            score = 0

        scored_lines.append((score, i, line))

    # Sort by score descending, keep top lines, re-sort by position
    scored_lines.sort(key=lambda x: x[0], reverse=True)

    selected = []
    char_count = 0

    for score, idx, line in scored_lines:
        if char_count + len(line) > max_chars:
            break
        selected.append((idx, line))
        char_count += len(line) + 1

    # Re-sort by original position
    selected.sort(key=lambda x: x[0])

    trimmed = "\n".join(line for _, line in selected)

    if len(trimmed) < len(document_text):
        trimmed += f"\n\n[Document trimmed from {len(document_text):,} to {len(trimmed):,} chars — most permit-relevant content preserved]"

    return trimmed


# ============================================================================
# PROMPT BUILDER
# ============================================================================


def build_analysis_prompt(
    document_text: str, requirements: dict, max_doc_chars: int = 15000
) -> str:
    """
    Build the full analysis prompt with city context, requirements, and document.
    This is where the magic happens - we inject everything the AI needs.
    """
    # Trim document
    trimmed_text = trim_document_smart(document_text, max_chars=max_doc_chars)

    # Build city context from requirements (uses gotchas + city_info)
    city_context = build_city_context(requirements)

    # Format requirements checklist
    items = requirements.get("items", [])
    requirements_list = "\n".join(
        [f"  {i + 1}. {item}" for i, item in enumerate(items)]
    )

    permit_name = requirements.get("name", "Building Permit")

    # Build inspection sequence if available
    inspections = requirements.get("inspections", [])
    inspection_note = ""
    if inspections:
        inspection_note = "\nINSPECTION SEQUENCE (for reference):\n"
        inspection_note += "\n".join(
            [f"  {i + 1}. {insp}" for i, insp in enumerate(inspections)]
        )

    prompt = f"""Analyze this permit document package for a {permit_name}.

=== CITY-SPECIFIC CONTEXT ===
{city_context}
{inspection_note}

=== REQUIRED DOCUMENTS / ITEMS TO VERIFY ===
{requirements_list}

=== UPLOADED DOCUMENT CONTENT ===
{trimmed_text}

=== YOUR TASK ===
Check EVERY required item above against the document content.
Also check EVERY city-specific gotcha listed above.
Flag anything that could cause this permit to be REJECTED.

Respond with ONLY this JSON structure:
{{
    "summary": "2-3 sentence executive summary. Lead with the most critical issue or confirm readiness.",
    "overall_status": "READY" or "NEEDS_ATTENTION" or "INCOMPLETE",
    "compliance_score": <0-100>,
    "items_found": [
        {{
            "requirement": "The requirement text",
            "status": "FOUND" or "MISSING" or "PARTIAL" or "UNCLEAR",
            "evidence": "Quote or describe where you found it. Be specific.",
            "recommendation": "Exact action needed if not FOUND. Include city-specific details."
        }}
    ],
    "critical_issues": ["Must-fix items that WILL cause rejection. Be specific about the city rule."],
    "recommendations": ["Nice-to-have improvements or things to double-check"],
    "city_warnings": ["City-specific gotchas that apply to THIS permit package"],
    "next_steps": ["Ordered actions the contractor should take right now"]
}}

IMPORTANT:
- Every item in the requirements list MUST appear in items_found
- If a city gotcha is relevant to the uploaded documents, include it in city_warnings
- compliance_score: 90-100 = ready to submit, 70-89 = minor fixes, 50-69 = significant gaps, below 50 = major rework needed
- Be the expert who saves the contractor from a rejection"""

    return prompt, trimmed_text


# ============================================================================
# GEMINI FLASH PROVIDER (Standard Tier)
# ============================================================================


def analyze_with_gemini(
    document_text: str,
    requirements: dict,
    api_key: str,
    model: str = "gemini-2.0-flash",
) -> dict:
    """
    Analyze permit document using Google Gemini Flash.
    Cost: ~$0.002-$0.01 per analysis
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

    prompt, trimmed_text = build_analysis_prompt(
        document_text, requirements, max_doc_chars=10000
    )

    try:
        gen_model = genai.GenerativeModel(
            model,
            system_instruction=SYSTEM_PROMPT,
        )
        response = gen_model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=4000,
                temperature=0.1,
            ),
        )

        response_text = response.text
        analysis = parse_analysis_response(response_text)

        # Estimate token usage
        est_input_tokens = (len(SYSTEM_PROMPT) + len(prompt)) // 4
        est_output_tokens = len(response_text) // 4

        analysis["_metadata"] = {
            "model": model,
            "provider": "google",
            "tier": "standard",
            "permit_type": requirements.get("name", ""),
            "city": requirements.get("city", ""),
            "requirements_checked": len(requirements.get("items", [])),
            "gotchas_injected": len(requirements.get("gotchas", [])),
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
    Higher quality, more nuanced analysis for paying customers.
    """
    client = anthropic.Anthropic(api_key=api_key)

    # Premium gets more document content
    prompt, trimmed_text = build_analysis_prompt(
        document_text, requirements, max_doc_chars=20000
    )

    try:
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            system=SYSTEM_PROMPT,
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
            "permit_type": requirements.get("name", ""),
            "city": requirements.get("city", ""),
            "requirements_checked": len(requirements.get("items", [])),
            "gotchas_injected": len(requirements.get("gotchas", [])),
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
        result = analyze_with_claude(document_text, requirements, anthropic_api_key)
        if result.get("overall_status") != "ERROR":
            return result
        if google_api_key:
            print("⚠️ Claude failed, falling back to Gemini Flash")
            return analyze_with_gemini(document_text, requirements, google_api_key)
        return result

    elif google_api_key:
        result = analyze_with_gemini(document_text, requirements, google_api_key)
        if result.get("overall_status") != "ERROR":
            return result
        if anthropic_api_key:
            print("⚠️ Gemini failed, falling back to Claude Sonnet")
            return analyze_with_claude(document_text, requirements, anthropic_api_key)
        return result

    elif anthropic_api_key:
        return analyze_with_claude(document_text, requirements, anthropic_api_key)

    else:
        return {
            "error": "No API Key",
            "message": "No AI provider API key configured. Set GOOGLE_API_KEY or ANTHROPIC_API_KEY.",
            "overall_status": "ERROR",
        }


# ============================================================================
# QUICK CHECK
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
            pass

    if anthropic_api_key:
        try:
            client = anthropic.Anthropic(api_key=anthropic_api_key)
            message = client.messages.create(
                model="claude-haiku-3-20240307",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return parse_analysis_response(message.content[0].text)
        except Exception:
            pass

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

    if google_key:
        return analyze_document(
            document_text,
            requirements,
            tier="standard",
            anthropic_api_key=api_key,
            google_api_key=google_key,
        )

    return analyze_with_claude(document_text, requirements, api_key, model)


# ============================================================================
# JSON PARSER
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

    # Import permit_data for a real test
    from permit_data import get_permit_requirements, get_city_key

    test_document = """
    BUILDING PERMIT APPLICATION
    City of Fort Lauderdale
    Property Address: 123 Ocean Drive, Fort Lauderdale, FL 33301
    Owner: John Smith
    Contractor: ABC Construction LLC - License #CGC123456
    Project Description: Kitchen remodel including new cabinets, countertops,
    and electrical upgrades for new appliances.
    Estimated Value: $45,000
    Insurance: Certificate of Liability - Holder: City of Fort Lauderdale
    Attachments:
    - Site plan (2 copies)
    - Electrical drawings
    - Notice of Commencement #2024-12345
    """

    # Use REAL requirements with gotchas
    city_key = get_city_key("Fort Lauderdale")
    test_requirements = get_permit_requirements(city_key, "building")

    print("=" * 60)
    print(
        f"Testing with {len(test_requirements.get('gotchas', []))} city gotchas injected"
    )
    print(f"City: {test_requirements.get('city', 'N/A')}")
    print(f"Permit: {test_requirements.get('name', 'N/A')}")
    print("=" * 60)

    result = analyze_document(
        test_document,
        test_requirements,
        tier="standard",
        anthropic_api_key=anthropic_key,
        google_api_key=google_key,
    )
    print(json.dumps(result, indent=2))
