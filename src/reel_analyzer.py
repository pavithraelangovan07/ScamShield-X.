import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import cv2
import pytesseract

WINDOWS_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if Path(WINDOWS_TESSERACT_PATH).exists():
    pytesseract.pytesseract.tesseract_cmd = WINDOWS_TESSERACT_PATH

_whisper_model = None


def load_whisper_model():
    global _whisper_model
    if _whisper_model is None:
        try:
            import whisper
        except ImportError as exc:
            raise RuntimeError("Whisper is not installed. Run: pip install openai-whisper") from exc
        print("Loading Whisper model (base) for the first Reel analysis...")
        _whisper_model = whisper.load_model("base")
    return _whisper_model


def check_ffmpeg():
    if shutil.which("ffmpeg") is None:
        raise RuntimeError("FFmpeg was not found. Install FFmpeg and make sure 'ffmpeg' works in PowerShell.")


def extract_audio(video_path):
    check_ffmpeg()
    fd, audio_path = tempfile.mkstemp(suffix=".wav")
    os.close(fd)
    command = ["ffmpeg", "-y", "-i", str(video_path), "-vn", "-acodec", "pcm_s16le", "-ar", "16000", "-ac", "1", audio_path]
    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return audio_path
    except subprocess.CalledProcessError as exc:
        if os.path.exists(audio_path): os.remove(audio_path)
        raise RuntimeError("FFmpeg could not extract audio from the Reel.") from exc


def transcribe_audio(video_path):
    audio_path = None
    try:
        audio_path = extract_audio(video_path)
        model = load_whisper_model()
        result = model.transcribe(audio_path, fp16=False)
        return str(result.get("text", "")).strip()
    except Exception as exc:
        print("Speech transcription warning:", exc)
        return ""
    finally:
        if audio_path and os.path.exists(audio_path): os.remove(audio_path)


def extract_ocr_text(video_path, sample_every_seconds=1.5, max_frames=40):
    capture = cv2.VideoCapture(str(video_path))
    if not capture.isOpened():
        return ""
    fps = capture.get(cv2.CAP_PROP_FPS) or 25
    interval = max(1, int(fps * sample_every_seconds))
    frame_no = 0
    sampled = 0
    texts = []
    while sampled < max_frames:
        ok, frame = capture.read()
        if not ok:
            break
        if frame_no % interval == 0:
            sampled += 1
            try:
                h, w = frame.shape[:2]
                if w < 1200:
                    scale = 1200 / max(w, 1)
                    frame = cv2.resize(frame, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                gray = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
                text = pytesseract.image_to_string(gray, config="--psm 6").strip()
                if text:
                    texts.append(text)
            except Exception as exc:
                print("OCR warning:", exc)
        frame_no += 1
    capture.release()
    unique = []
    for text in texts:
        normalized = " ".join(text.split())
        if normalized and normalized not in unique:
            unique.append(normalized)
    return "\n".join(unique)


def analyze_reel(video_path, caption=""):
    caption = str(caption or "").strip()
    transcript = transcribe_audio(video_path)
    ocr_text = extract_ocr_text(video_path)
    parts = []
    if caption: parts.append("Instagram caption: " + caption)
    if transcript: parts.append("Spoken content: " + transcript)
    if ocr_text: parts.append("Text visible in video: " + ocr_text)
    return {"caption": caption, "transcript": transcript, "ocr_text": ocr_text, "combined_text": "\n".join(parts)}
