"""
PermitPro AI - Document Reader Module (Enhanced with OCR)
Extracts text from PDFs (native + scanned) and images.

Dependencies:
    pip install PyMuPDF Pillow pytesseract
    Also requires Tesseract OCR engine:
        Ubuntu:  sudo apt-get install tesseract-ocr
        Mac:     brew install tesseract
"""

import fitz  # PyMuPDF
from PIL import Image
import io
import os


# ============================================================================
# OCR SETUP
# ============================================================================

# Try to import pytesseract - graceful degradation if not installed
try:
    import pytesseract

    # Windows: Tesseract installs here by default but isn't added to PATH
    import platform

    if platform.system() == "Windows":
        pytesseract.pytesseract.tesseract_cmd = (
            r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        )
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    print("⚠️  pytesseract not installed. Scanned PDFs and images won't be readable.")
    print("   Install: pip install pytesseract")
    print("   Also need Tesseract engine: sudo apt-get install tesseract-ocr")


def ocr_image(image: Image.Image) -> str:
    """
    Run OCR on a PIL Image. Returns extracted text or empty string.
    Preprocesses image for better OCR accuracy on permit documents.
    """
    if not OCR_AVAILABLE:
        return ""

    try:
        # Convert to grayscale for better OCR
        gray = image.convert("L")

        # Resize if too small (OCR works better on larger images)
        w, h = gray.size
        if w < 1000:
            scale = 1500 / w
            gray = gray.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        # Run OCR with permit-friendly config
        # PSM 6 = assume uniform block of text (good for forms)
        # OEM 3 = default LSTM engine
        custom_config = r"--oem 3 --psm 6"
        text = pytesseract.image_to_string(gray, config=custom_config)

        return text.strip()

    except Exception as e:
        print(f"  ⚠️  OCR failed: {e}")
        return ""


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


def get_document_text(file_path: str, is_blueprint: bool = False) -> str:
    """
    Extract text from PDF or image files.

    Pipeline:
        1. PDF with native text → PyMuPDF direct extraction
        2. PDF with scanned pages → render page to image → OCR
        3. Image files (PNG/JPG) → OCR directly

    Args:
        file_path: Path to the document file
        is_blueprint: Reserved for future blueprint-specific handling

    Returns:
        Extracted text string, or error message
    """
    if not os.path.exists(file_path):
        return f"Error: File not found: {file_path}"

    file_lower = file_path.lower()

    try:
        # Route to appropriate extractor
        if file_lower.endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp")):
            return extract_text_from_image(file_path)
        elif file_lower.endswith(".pdf"):
            return extract_text_from_pdf(file_path)
        else:
            return "Error: Unsupported file type. Please upload a PDF or image file."

    except Exception as e:
        return f"Error reading document: {str(e)}\nPlease try a different file or contact support."


# ============================================================================
# PDF EXTRACTION
# ============================================================================


def extract_text_from_pdf(file_path: str) -> str:
    """
    Extract text from PDF. Uses native text extraction first,
    falls back to OCR for scanned pages.
    """
    doc = fitz.open(file_path)
    text_parts = []
    ocr_pages = 0
    total_pages = len(doc)

    for page_num in range(total_pages):
        page = doc.load_page(page_num)

        # Try native text extraction first (fast, accurate)
        page_text = page.get_text().strip()

        if page_text and len(page_text) > 50:
            # Good native text found
            text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}")
        else:
            # No native text - this is likely a scanned page
            # Render page to image and OCR it
            ocr_text = ocr_pdf_page(page)
            if ocr_text and len(ocr_text) > 20:
                text_parts.append(f"--- Page {page_num + 1} (scanned) ---\n{ocr_text}")
                ocr_pages += 1
            elif page_text:
                # Had some text, just not much - include it anyway
                text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}")
            else:
                text_parts.append(
                    f"--- Page {page_num + 1} ---\n[Page appears to be blank or contains only graphics]"
                )

    doc.close()

    full_text = "\n\n".join(text_parts)

    # Add extraction summary
    summary_parts = [f"[Extracted {total_pages} page(s)"]
    if ocr_pages > 0:
        summary_parts.append(f", {ocr_pages} via OCR")
    summary_parts.append("]")

    if not full_text.strip() or all(
        "[Page appears to be blank" in p for p in text_parts
    ):
        return (
            "Error: No readable text could be extracted from this PDF. "
            "The document may be corrupted or contain only images without text."
        )

    return "".join(summary_parts) + "\n\n" + full_text


def ocr_pdf_page(page) -> str:
    """
    Render a PDF page to an image and run OCR on it.
    Uses 300 DPI for good accuracy on permit documents.
    """
    if not OCR_AVAILABLE:
        return "[Scanned page detected but OCR not available - install pytesseract]"

    try:
        # Render page at 300 DPI (good balance of quality vs speed)
        mat = fitz.Matrix(300 / 72, 300 / 72)
        pix = page.get_pixmap(matrix=mat)

        # Convert to PIL Image
        img_data = pix.tobytes("png")
        image = Image.open(io.BytesIO(img_data))

        return ocr_image(image)

    except Exception as e:
        print(f"  ⚠️  Page OCR failed: {e}")
        return ""


# ============================================================================
# IMAGE EXTRACTION
# ============================================================================


def extract_text_from_image(image_path: str) -> str:
    """
    Extract text from an image file using OCR.
    Handles PNG, JPG, TIFF, BMP.
    """
    if not OCR_AVAILABLE:
        return (
            "Image file detected but OCR is not available.\n"
            "For best results, please upload a PDF version of your document.\n"
            "[To enable image reading: pip install pytesseract && sudo apt-get install tesseract-ocr]"
        )

    try:
        image = Image.open(image_path)

        w, h = image.size
        fmt = image.format or os.path.splitext(image_path)[1].upper()
        print(f"  📷 Processing image: {w}x{h} {fmt}")

        text = ocr_image(image)

        if text and len(text) > 20:
            return f"[Extracted from image ({w}x{h})]\n\n{text}"
        else:
            return (
                f"Image file detected ({w}x{h}) but very little text could be extracted.\n"
                "This may be a photo, blueprint, or low-quality scan.\n"
                "For best results, please upload a clear PDF version."
            )

    except Exception as e:
        return f"Error processing image: {str(e)}\nPlease try a different file."


# ============================================================================
# CLI TESTING
# ============================================================================

if __name__ == "__main__":
    import sys

    print(f"OCR Available: {OCR_AVAILABLE}")

    if len(sys.argv) > 1:
        result = get_document_text(sys.argv[1])
        print(f"\n{'=' * 60}")
        print(f"Extracted text ({len(result)} chars):")
        print(f"{'=' * 60}")
        print(result[:3000])
        if len(result) > 3000:
            print(f"\n... [{len(result) - 3000} more characters]")
    else:
        print("Usage: python reader.py <file_path>")
