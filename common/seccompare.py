import json
import hashlib
import os
from typing import Any

import requests

SECCOMPARE_URL = os.getenv("SECCOMPARE_URL", "https://seccompare.com")


def upload_if_missing(profile: Any, image: str = "") -> None:
    """Upload seccomp profile to seccompare.com if not already present."""
    try:
        payload = json.dumps(profile, sort_keys=True)
        hash_val = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        check_resp = requests.post(
            f"{SECCOMPARE_URL}/api/check-hash",
            json={"hash": hash_val},
            timeout=5,
        )
        exists = check_resp.ok and check_resp.json().get("exists")
        if exists:
            return
        upload_data = {
            "hash": hash_val,
            "json": profile,
            "image": image,
            "uploadType": "auto",
            "source": "seccomp-diff",
        }
        requests.post(
            f"{SECCOMPARE_URL}/api/upload",
            json=upload_data,
            timeout=5,
        )
    except Exception as e:
        # Log the error but don't interrupt normal flow
        print(f"seccompare sync failed: {e}")

