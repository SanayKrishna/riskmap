"""Snapshot integrity — HMAC-SHA256 over canonical JSON. No Flask, no AI.

The HMAC key is derived from the SECRET_KEY environment variable (falling back
to a fixed dev key when it is unset). Snapshots signed under one key will
therefore show as "tampered" if SECRET_KEY changes. That is expected behaviour:
the signature can no longer be reproduced, so it cannot be vouched for.

Keep SECRET_KEY stable across restarts and deployments. Unlike a plain hash,
someone who can edit the snapshot file cannot recompute a valid signature
without also knowing the key.
"""

import hashlib
import hmac
import json
import os

VERIFIED, TAMPERED, MISSING = "verified", "tampered", "missing"


def _key():
    return os.environ.get("SECRET_KEY", "dev-insecure-key").encode()


def canonical_json(data):
    """Deterministic encoding: sorted keys, no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sign_snapshot(risk_data):
    """Hex HMAC-SHA256 of the canonical JSON of risk_data."""
    msg = canonical_json(risk_data).encode("utf-8")
    return hmac.new(_key(), msg, digestmod=hashlib.sha256).hexdigest()


def verify_snapshot(risk_data, stored_hash):
    """True when the recomputed HMAC matches stored_hash (constant-time compare)."""
    if not isinstance(stored_hash, str) or not stored_hash:
        return False
    return hmac.compare_digest(sign_snapshot(risk_data), stored_hash)


def check_snapshot(risk_data, stored_hash):
    """'verified' | 'tampered' | 'missing' (no hash stored, or the check errored)."""
    if stored_hash is None or stored_hash == "":
        return MISSING
    try:
        return VERIFIED if verify_snapshot(risk_data, stored_hash) else TAMPERED
    except Exception:
        return MISSING
