"""Server-side validation helpers."""
import re

GSTIN_RE = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$")
PHONE_RE = re.compile(r"^[0-9]{10}$")


def validate_phone(phone):
    """10 digits exactly (country code handled separately)."""
    if not phone:
        return True, ""   # optional
    phone = phone.strip()
    if PHONE_RE.match(phone):
        return True, ""
    return False, "Phone must be exactly 10 digits."


def validate_gst(gst):
    """Optional, but if present must be a valid 15-char GSTIN."""
    if not gst:
        return True, ""
    gst = gst.strip().upper()
    if GSTIN_RE.match(gst):
        return True, ""
    return False, "GST must be a valid 15-character GSTIN (e.g. 24ABCDE1234F1Z5)."


def validate_required(fields):
    """fields: dict label->value. Returns (ok, msg)."""
    missing = [label for label, val in fields.items() if not (val or "").strip()]
    if missing:
        return False, "Required: " + ", ".join(missing)
    return True, ""


# common country dial codes
DIAL_CODES = [
    ("+91", "India"), ("+1", "USA/Canada"), ("+44", "UK"), ("+971", "UAE"),
    ("+61", "Australia"), ("+49", "Germany"), ("+33", "France"), ("+86", "China"),
    ("+81", "Japan"), ("+65", "Singapore"), ("+60", "Malaysia"), ("+966", "Saudi"),
    ("+880", "Bangladesh"), ("+94", "Sri Lanka"), ("+977", "Nepal"), ("+27", "S.Africa"),
    ("+55", "Brazil"), ("+7", "Russia"), ("+39", "Italy"), ("+34", "Spain"),
    ("+31", "Netherlands"), ("+82", "S.Korea"), ("+64", "New Zealand"), ("+20", "Egypt"),
]
