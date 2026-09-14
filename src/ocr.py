from pathlib import Path
from PIL import Image
import pytesseract

WINDOWS_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if Path(WINDOWS_TESSERACT_PATH).exists():
    pytesseract.pytesseract.tesseract_cmd = WINDOWS_TESSERACT_PATH


def extract_text_from_image(image_path, languages="eng"):
    image = Image.open(image_path).convert("RGB")
    return pytesseract.image_to_string(image, lang=languages).strip()


def extract_multilingual_text(image_path):
    for language in ["eng", "eng+tam", "eng+hin"]:
        try:
            text = extract_text_from_image(image_path, language)
            if text:
                return {"text": text, "ocr_language": language}
        except Exception:
            continue
    return {"text": "", "ocr_language": "eng"}
