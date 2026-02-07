"""
Gemini Flash provider for Flo Permit - Standard tier AI analysis
Drop-in replacement for Claude calls on free/standard tier to cut costs ~95%

Usage in main.py:
    from gemini_provider import analyze_with_gemini, get_google_key
"""

import os
import json
import re


def get_google_key():
    """Get Google API key from environment"""
    return os.getenv("GOOGLE_API_KEY")


def analyze_with_gemini(prompt: str, max_tokens: int = 4096) -> dict:
    """
    Call Gemini 2.0 Flash with the same prompt used for Claude.
    Returns dict with: response_text, input_tokens, output_tokens, cost_cents, model
    """
    import google.generativeai as genai

    api_key = get_google_key()
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not configured")

    genai.configure(api_key=api_key)

    model = genai.GenerativeModel(
        "gemini-2.0-flash",
        generation_config=genai.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=0.1,  # Low temp for consistent permit analysis
        ),
    )

    response = model.generate_content(prompt)

    # Extract token counts
    usage = response.usage_metadata
    input_tokens = getattr(usage, "prompt_token_count", 0)
    output_tokens = getattr(usage, "candidates_token_count", 0)

    # Gemini 2.0 Flash pricing: ~$0.10/1M input, ~$0.40/1M output
    cost_cents = round((input_tokens * 0.0001 + output_tokens * 0.0004) * 100, 2)

    return {
        "response_text": response.text,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "cost_cents": max(1, int(cost_cents)),  # minimum 1 cent for tracking
        "model": "gemini-2.0-flash",
    }


def parse_analysis_json(response_text: str) -> dict:
    """Parse JSON from AI response - works for both Claude and Gemini output"""
    for pattern in [r"```json\s*([\s\S]*?)\s*```", r"\{[\s\S]*\}"]:
        matches = re.findall(pattern, response_text)
        for m in matches:
            try:
                parsed = json.loads(m.strip() if m.strip().startswith("{") else m)
                if "summary" in parsed or "compliance_score" in parsed:
                    # Flatten nested objects for backward compatibility
                    if parsed.get("documents_found") and isinstance(
                        parsed["documents_found"][0], dict
                    ):
                        parsed["documents_found_detailed"] = parsed["documents_found"]
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
                            d.get("name", str(d)) for d in parsed["missing_documents"]
                        ]
                    if parsed.get("critical_issues") and isinstance(
                        parsed["critical_issues"][0], dict
                    ):
                        parsed["critical_issues_detailed"] = parsed["critical_issues"]
                        parsed["critical_issues"] = [
                            d.get("issue", str(d)) for d in parsed["critical_issues"]
                        ]
                    return parsed
            except (json.JSONDecodeError, IndexError, TypeError):
                continue

    return {
        "summary": response_text[:500],
        "compliance_score": 50,
        "overall_status": "NEEDS_REVIEW",
    }
