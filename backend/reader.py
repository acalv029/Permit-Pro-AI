import fitz  # PyMuPDF
from PIL import Image
import io


def get_document_text(file_path, is_blueprint=False):
    """
    Extract text from PDF or image files.
    Uses PyMuPDF for text extraction - lightweight and fast.
    """
    try:
        # Check if it's an image file
        if file_path.lower().endswith((".png", ".jpg", ".jpeg")):
            return extract_text_from_image(file_path)

        # Handle PDF files
        doc = fitz.open(file_path)
        text_parts = []

        for page_num in range(len(doc)):
            page = doc.load_page(page_num)

            # Extract text directly from PDF
            page_text = page.get_text()

            if page_text.strip():
                text_parts.append(page_text)
            else:
                # If no text found, try extracting from images in the page
                image_text = extract_text_from_page_images(page)
                if image_text:
                    text_parts.append(image_text)

        doc.close()

        full_text = "\n".join(text_parts)

        # If we still have no text, return a helpful message
        if not full_text.strip():
            return "No text could be extracted from this document. Please ensure the document contains readable text or try a different file."

        return full_text

    except Exception as e:
        return f"Error reading document: {str(e)}\nPlease try a different file or contact support."


def extract_text_from_image(image_path):
    """
    Extract text from image files.
    Note: For production use, you may want to add pytesseract for better OCR.
    This is a basic implementation.
    """
    try:
        # For now, we'll return a message asking for PDF
        # In production, you'd use pytesseract here
        return "Image file detected. For best results, please upload a PDF version of your document."
    except Exception as e:
        return f"Error processing image: {str(e)}"


def extract_text_from_page_images(page):
    """
    Extract text from images embedded in a PDF page.
    """
    text_parts = []

    try:
        # Get list of images on the page
        image_list = page.get_images()

        for img_index, img in enumerate(image_list):
            # This is a basic implementation
            # For production, you'd extract the image and use OCR
            pass

    except Exception as e:
        pass

    return "\n".join(text_parts)


if __name__ == "__main__":
    # Test the function
    import sys

    if len(sys.argv) > 1:
        result = get_document_text(sys.argv[1])
        print(result)
    else:
        print("Usage: python reader.py <file_path>")
