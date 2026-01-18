import anthropic
import os


def analyze_document_with_claude(document_text, permit_requirements, api_key):
    """
    Analyze permit documents using Claude AI.
    Returns a well-formatted analysis with clean bullet points.
    """

    if not api_key or api_key == "your-api-key-here":
        return analyze_document_mock(document_text, permit_requirements)

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Build the requirements list
        requirements_list = "\n".join(
            [f"  • {item}" for item in permit_requirements["items"]]
        )

        prompt = f"""You are a professional South Florida building permit expert and document reviewer.

**PERMIT TYPE:** {permit_requirements["name"]}

**REQUIRED ITEMS FOR THIS PERMIT:**
{requirements_list}

**DOCUMENT TO ANALYZE:**
{document_text[:8000]}

---

Please analyze this document thoroughly and provide a detailed report in the following format:

## ✅ ITEMS FOUND (Correct)
For each requirement that IS present in the document, list it as:
• [Requirement name] - [Brief note about where/how it was found]

## ❌ ITEMS MISSING (Action Required)
For each requirement that is NOT present or incomplete, list it as:
• [Requirement name] - [Why it's missing or what's needed]

## 💡 RECOMMENDATIONS
Provide 3-5 specific, actionable recommendations to improve this application.

## 🎯 OVERALL STATUS
Provide one of:
- 🟢 READY TO SUBMIT - All requirements met
- 🟡 NEEDS MINOR FIXES - Most requirements met, minor items missing
- 🔴 NEEDS MAJOR WORK - Critical requirements missing

Then provide a 2-3 sentence summary of the application status.

---

**IMPORTANT FORMATTING RULES:**
- Use bullet points (•) for each item
- Be specific about what was found and what's missing
- Keep each bullet point to 1-2 lines maximum
- Be professional but clear and direct
"""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}],
        )

        return message.content[0].text

    except Exception as e:
        return (
            f"❌ **API Error:** {str(e)}\n\nFalling back to basic analysis...\n\n"
            + analyze_document_mock(document_text, permit_requirements)
        )


def analyze_document_mock(document_text, permit_requirements):
    """
    Fallback analyzer when API key is not available.
    Uses simple keyword matching.
    """

    found_items = []
    missing_items = []

    # Simple keyword detection
    for item in permit_requirements["items"]:
        keywords = [word.lower() for word in item.split()[:3]]
        if any(
            keyword in document_text.lower() for keyword in keywords if len(keyword) > 3
        ):
            found_items.append(item)
        else:
            missing_items.append(item)

    # Build formatted report
    analysis = f"""## 📊 Document Analysis Report

### ✅ ITEMS FOUND ({len(found_items)} of {len(permit_requirements["items"])})
"""

    if found_items:
        for item in found_items:
            analysis += f"• {item}\n"
    else:
        analysis += "• No items clearly identified\n"

    analysis += f"\n### ❌ ITEMS MISSING ({len(missing_items)} of {len(permit_requirements['items'])})\n"

    if missing_items:
        for item in missing_items:
            analysis += f"• {item}\n"
    else:
        analysis += "• All items appear to be present\n"

    analysis += """
### 💡 RECOMMENDATIONS
• Review the document to ensure all required items are clearly labeled
• Verify that all information is complete and accurate
• Consider adding a checklist to track requirements
• Ensure all signatures and dates are present where required

### 🎯 OVERALL STATUS
"""

    if len(missing_items) == 0:
        analysis += "🟢 **READY TO SUBMIT** - All requirements appear to be met\n"
    elif len(missing_items) <= 2:
        analysis += "🟡 **NEEDS MINOR FIXES** - Most requirements met, few items need attention\n"
    else:
        analysis += "🔴 **NEEDS MAJOR WORK** - Multiple critical requirements missing\n"

    analysis += f"\n**Note:** This is a basic keyword analysis. For detailed AI-powered analysis, please add your Anthropic API key in settings."

    return analysis
