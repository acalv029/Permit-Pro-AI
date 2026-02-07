"""
Flo Permit - Gemini Integration Patcher
Run this ONCE to add Gemini Flash support to main.py
"""

import re
import sys
import shutil
from pathlib import Path


def patch_main():
    main_path = Path("main.py")

    if not main_path.exists():
        print("main.py not found! Run this script from your backend folder.")
        sys.exit(1)

    content = main_path.read_text(encoding="utf-8")

    if "analyze_with_gemini" in content:
        print("Gemini integration already applied! Skipping.")
        sys.exit(0)

    backup_path = Path("main.py.backup")
    shutil.copy2(main_path, backup_path)
    print(f"Backup created: {backup_path}")

    changes_made = 0

    # EDIT 1: Add gemini_provider import
    old = "from analyzer import analyze_document_with_claude"
    new = """from analyzer import analyze_document_with_claude
from gemini_provider import analyze_with_gemini, get_google_key, parse_analysis_json"""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 1: Added gemini_provider import")

    # EDIT 2: Add tier parameter to endpoint
    old = """    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    \"\"\"Analyze permit folder\"\"\""""
    new = """    tier: str = Form("standard"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    \"\"\"Analyze permit folder\"\"\""""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 2: Added tier parameter to endpoint")

    # EDIT 3: Add tier routing before analyze call
    old = """        analysis = analyze_folder_with_claude(
            "\\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=user_id,
            analysis_uuid=analysis_id,
            db_session=db,
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        if user_id:"""
    new = """        # Determine AI tier based on subscription
        ai_tier = "standard"  # default: Gemini Flash (cheap)
        if user and user.subscription_tier in ("pro", "business"):
            ai_tier = "premium"  # Claude Sonnet (better quality)

        analysis = analyze_folder_with_claude(
            "\\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=user_id,
            analysis_uuid=analysis_id,
            db_session=db,
            tier=ai_tier,
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        if user_id:"""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 3: Added tier routing logic")

    # EDIT 4: Add tier param to function signature
    old = """def analyze_folder_with_claude(
    text: str,
    requirements: dict,
    api_key: str,
    file_count: int,
    user_id: int = None,
    analysis_uuid: str = None,
    db_session=None,
) -> dict:"""
    new = """def analyze_folder_with_claude(
    text: str,
    requirements: dict,
    api_key: str,
    file_count: int,
    user_id: int = None,
    analysis_uuid: str = None,
    db_session=None,
    tier: str = "standard",
) -> dict:"""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 4: Added tier parameter to function signature")

    # EDIT 5: Add Gemini block before Claude try block
    old = """    try:
        msg = client.messages.create(
            model="claude-sonnet-4-20250514","""
    new = """    # STANDARD TIER: Use Gemini Flash (95% cheaper)
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
            model="claude-sonnet-4-20250514","""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 5: Added Gemini Flash block with fallback")

    # EDIT 6: Give single purchases premium tier
    old = """        analysis = analyze_folder_with_claude(
            "\\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=None,
            analysis_uuid=analysis_id,
            db_session=db,
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        # Mark purchase as used"""
    new = """        analysis = analyze_folder_with_claude(
            "\\n".join(all_text),
            requirements,
            api_key,
            len(processed_files),
            user_id=None,
            analysis_uuid=analysis_id,
            db_session=db,
            tier="premium",
        )

        file_tree = [{"name": p["name"], "size": p["size"]} for p in processed_files]

        # Mark purchase as used"""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 6: Single purchases now use premium tier")

    # EDIT 7: Update startup message
    old = """    print(f"   Resend Key: {'✅' if os.getenv('RESEND_API_KEY') else '❌'}")"""
    new = """    print(f"   Resend Key: {'✅' if os.getenv('RESEND_API_KEY') else '❌'}")
    print(f"   Google Key: {'✅' if os.getenv('GOOGLE_API_KEY') else '❌ (Gemini disabled)'}")"""
    if old in content:
        content = content.replace(old, new, 1)
        changes_made += 1
        print("Edit 7: Updated startup message")

    if changes_made == 0:
        print("No changes applied. Your main.py format may differ.")
        sys.exit(1)

    main_path.write_text(content, encoding="utf-8")
    print(f"\n{'=' * 50}")
    print(f"{changes_made}/7 edits applied successfully!")
    print(f"Backup at: {backup_path}")
    print(f"\nNext: add 'google-generativeai>=0.4.0' to requirements.txt")
    print(f"Then set GOOGLE_API_KEY in Railway and push to GitHub")


if __name__ == "__main__":
    patch_main()
