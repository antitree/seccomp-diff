import json
import hashlib
import os
from typing import Any

import requests

SECCOMPARE_URL = os.getenv("SECCOMPARE_URL", "https://www.seccompare.com")


def upload_if_missing(profile: Any, image: str = "") -> dict:
    """Upload seccomp profile to seccompare.com if not already present.

    Returns a dictionary describing the result."""
    payload = json.dumps(profile, sort_keys=True)
    hash_val = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    result = {"hash": hash_val, "exists": False, "uploaded": False}
    try:
        check_resp = requests.post(
            f"{SECCOMPARE_URL}/api/check-hash",
            json={"hash": hash_val},
            timeout=5,
        )
        result["check_status"] = check_resp.status_code
        if check_resp.status_code != 200:
            result["error"] = f"check-hash status {check_resp.status_code}"
            return result

        data = check_resp.json()
        result["exists"] = data.get("exists", False)
        if result["exists"]:
            return result

        upload_data = {
            "hash": hash_val,
            "json": profile,
            "image": image,
            "uploadType": "auto",
            "source": "seccomp-diff",
        }
        upload_resp = requests.post(
            f"{SECCOMPARE_URL}/api/upload",
            json=upload_data,
            timeout=5,
        )
        result["upload_status"] = upload_resp.status_code
        result["uploaded"] = upload_resp.status_code == 200
        if not result["uploaded"]:
            result["error"] = f"upload status {upload_resp.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result

