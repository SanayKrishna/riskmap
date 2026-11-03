"""Upload validation — size, MIME, JSON schema. No Flask, no AI."""

import json

from werkzeug.utils import secure_filename

MAX_UPLOAD_BYTES = 512 * 1024
MAX_RISKS = 50
ALLOWED_MIMES = ("application/json", "text/plain")
CATEGORIES = ("Technical", "Resource", "Schedule", "Cost", "External", "Quality")

MAX_ID = 20
MAX_TITLE = 200
MAX_DESCRIPTION = 2000
MAX_PROJECT_FIELD = 200


class UploadRejected(ValueError):
    """A ValueError that also says which security event it should be logged as."""

    def __init__(self, message, event_type="UPLOAD_REJECTED", severity="WARN"):
        super().__init__(message)
        self.event_type = event_type
        self.severity = severity


def read_upload(uploaded):
    """Check an uploaded file (size, MIME, filename) and return (filename, text)."""
    name = secure_filename(uploaded.filename or "") or "upload.json"
    mime = (uploaded.mimetype or "").lower()
    if mime not in ALLOWED_MIMES:
        raise UploadRejected(
            f"unsupported file type {mime or 'unknown'!r} — upload JSON (application/json or text/plain)."
        )
    raw = uploaded.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise UploadRejected(
            f"file is larger than {MAX_UPLOAD_BYTES // 1024} KB.", "OVERSIZED_UPLOAD"
        )
    try:
        return name, raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadRejected("file is not valid UTF-8 text.")


def parse_json(text, what):
    """json.loads with a size cap; failures become INVALID_JSON rejections."""
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise UploadRejected(
            f"{what} is larger than {MAX_UPLOAD_BYTES // 1024} KB.", "OVERSIZED_UPLOAD"
        )
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise UploadRejected(f"{what} is not valid JSON: {str(exc)[:120]}", "INVALID_JSON")


def _bad(rid, msg):
    return UploadRejected(f"risk {rid!r}: {msg}")


def validate_risks(risks):
    """Strict schema check. Raises UploadRejected on the first violation."""
    if not isinstance(risks, list) or not risks:
        raise UploadRejected("at least one risk is required.")
    if len(risks) > MAX_RISKS:
        raise UploadRejected(f"too many risks ({len(risks)}); the limit is {MAX_RISKS} per submission.")
    for i, r in enumerate(risks, 1):
        if not isinstance(r, dict):
            raise UploadRejected(f"risk #{i} must be an object.")
        rid = r.get("id", f"#{i}")
        if not isinstance(r.get("id"), str) or not r["id"].strip() or len(r["id"]) > MAX_ID:
            raise _bad(rid, f"id must be a non-empty string of at most {MAX_ID} characters.")
        if not isinstance(r.get("title"), str) or not r["title"].strip() or len(r["title"]) > MAX_TITLE:
            raise _bad(rid, f"title must be a non-empty string of at most {MAX_TITLE} characters.")
        for field in ("probability", "impact"):
            v = r.get(field)
            if isinstance(v, bool) or type(v) is not int or not 1 <= v <= 5:
                raise _bad(rid, f"{field} must be an integer from 1 to 5.")
        if r.get("category") not in CATEGORIES:
            raise _bad(rid, f"category must be one of {', '.join(CATEGORIES)}.")
        desc = r.get("description")
        if desc is not None and (not isinstance(desc, str) or len(desc) > MAX_DESCRIPTION):
            raise _bad(rid, f"description must be text of at most {MAX_DESCRIPTION} characters.")
        trig = r.get("triggers")
        if trig is not None and (
            not isinstance(trig, list) or len(trig) > MAX_RISKS
            or any(not isinstance(t, str) or len(t) > MAX_ID for t in trig)
        ):
            raise _bad(rid, "triggers must be a list of risk ids.")


def validate_project_fields(**fields):
    for name, value in fields.items():
        limit = 8 if name == "currency" else MAX_PROJECT_FIELD
        if not isinstance(value, str) or len(value) > limit:
            raise UploadRejected(f"{name} must be text of at most {limit} characters.")
