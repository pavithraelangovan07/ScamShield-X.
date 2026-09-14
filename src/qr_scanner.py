import cv2


def scan_qr_code(image_path):
    image = cv2.imread(str(image_path))
    if image is None:
        return {"detected": False, "data": [], "error": "Unable to read image."}
    detector = cv2.QRCodeDetector()
    results = []
    try:
        result = detector.detectAndDecodeMulti(image)
        if len(result) == 4:
            success, decoded_info, _, _ = result
            if success:
                results.extend([v.strip() for v in decoded_info if v and v.strip()])
    except Exception:
        pass
    if not results:
        try:
            data, _, _ = detector.detectAndDecode(image)
            if data and data.strip():
                results.append(data.strip())
        except Exception:
            pass
    return {"detected": bool(results), "data": list(dict.fromkeys(results))}
