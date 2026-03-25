#!/usr/bin/env python3
"""
CTF::SOLVER — Platform Connectors
Handles authentication, challenge fetching, file downloads, and flag submission
for picoCTF, CTFd-based platforms, and HackTheBox.
"""

import json
import os
import re
import time
from typing import Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─── Base ─────────────────────────────────────────────────────────────────────

class PlatformError(Exception):
    pass

class BasePlatform:
    name      = "base"
    base_url  = ""

    def __init__(self, config: dict):
        self.config   = config
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.token    = config.get("token", "")
        self.base_url = config.get("url", self.base_url).rstrip("/")
        self.session  = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.verify = False
            self.session.headers.update({"User-Agent": "CTF-Solver/1.0"})

    def login(self) -> str:
        return f"No login flow implemented for platform type '{self.name}'."

    def get_challenges(self) -> list:
        return []

    def submit_flag(self, challenge_id, flag: str) -> dict:
        return {
            "correct": False,
            "message": f"submit_flag not implemented for platform type '{self.name}'",
            "challenge_id": challenge_id,
        }

    def download_file(self, url: str, dest_path: str) -> str:
        """Download a file to dest_path. Returns the local path."""
        if not HAS_REQUESTS:
            return "requests not installed"
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        resp = self.session.get(url, stream=True, timeout=30)
        resp.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return dest_path

    def _req(self, method, path, **kwargs):
        if not self.session:
            raise PlatformError("requests not available")
        url = path if path.startswith("http") else self.base_url + path
        resp = self.session.request(method, url, timeout=20, **kwargs)
        resp.raise_for_status()
        return resp


# ─── picoCTF ──────────────────────────────────────────────────────────────────

class PicoCTF(BasePlatform):
    name     = "picoctf"
    base_url = "https://play.picoctf.org"

    def login(self) -> str:
        if self.token:
            self.session.headers["Authorization"] = f"Token {self.token}"
            return "Logged in with token"

        resp = self._req("POST", "/api/v1/user/login/", json={
            "username": self.username,
            "password": self.password,
        })
        data = resp.json()
        token = data.get("token") or data.get("key")
        if token:
            self.token = token
            self.session.headers["Authorization"] = f"Token {token}"
            return f"Logged in as {self.username}"
        raise PlatformError(f"Login failed: {data}")

    def get_challenges(self) -> list:
        # Fetch all pages
        challenges = []
        page = 1
        while True:
            resp = self._req("GET", f"/api/v1/challenges/?page={page}&page_size=100")
            data = resp.json()
            results = data.get("results") or data.get("data") or data
            if not results:
                break
            for ch in results:
                challenges.append(self._normalise(ch))
            if not data.get("next"):
                break
            page += 1
        return challenges

    def _normalise(self, ch: dict) -> dict:
        return {
            "platform_id": str(ch.get("id", "")),
            "name":        ch.get("name", "Unknown"),
            "category":    ch.get("category", "Misc"),
            "points":      ch.get("score") or ch.get("value") or 0,
            "description": ch.get("description") or ch.get("details", ""),
            "solved":      ch.get("solved", False),
            "files":       ch.get("files") or [],
            "hints":       ch.get("hints") or [],
            "instance":    ch.get("instance_name") or "",
            "difficulty":  _difficulty_from_points(ch.get("score") or ch.get("value") or 0),
        }

    def submit_flag(self, challenge_id, flag: str) -> dict:
        resp = self._req("POST", f"/api/v1/challenges/{challenge_id}/submit/",
                         json={"flag": flag.strip()})
        data = resp.json()
        correct = data.get("correct") or data.get("success") or "correct" in str(data).lower()
        return {"correct": bool(correct), "message": str(data)}


# ─── CTFd (generic — used by most competitions) ───────────────────────────────

class CTFd(BasePlatform):
    name = "ctfd"

    def login(self) -> str:
        if self.token:
            self.session.headers["Authorization"] = f"Token {self.token}"
            # Verify token works
            try:
                self._req("GET", "/api/v1/users/me")
                return "Logged in with token"
            except Exception:
                pass

        # Get CSRF nonce
        resp = self.session.get(self.base_url + "/login", timeout=10)
        nonce_match = re.search(r'name="nonce"\s+value="([^"]+)"', resp.text)
        nonce = nonce_match.group(1) if nonce_match else ""

        resp = self.session.post(self.base_url + "/login", data={
            "name":     self.username,
            "password": self.password,
            "nonce":    nonce,
            "_submit":  "Submit",
        }, allow_redirects=True, timeout=15)

        if "incorrect" in resp.text.lower() or "invalid" in resp.text.lower():
            raise PlatformError("Login failed — check username/password")

        # Try to get token from API
        try:
            resp2 = self._req("GET", "/api/v1/users/me")
            self.user_id = resp2.json().get("data", {}).get("id")
        except Exception:
            pass

        return f"Logged in as {self.username}"

    def get_challenges(self) -> list:
        resp = self._req("GET", "/api/v1/challenges")
        data = resp.json().get("data", [])
        challenges = []
        for ch in data:
            # Fetch full details per challenge for description + files
            try:
                detail = self._req("GET", f"/api/v1/challenges/{ch['id']}").json().get("data", ch)
            except Exception:
                detail = ch
            challenges.append(self._normalise(detail))
        return challenges

    def _normalise(self, ch: dict) -> dict:
        files = []
        for f in ch.get("files") or []:
            url = f if f.startswith("http") else self.base_url + f
            files.append(url)
        return {
            "platform_id": str(ch.get("id", "")),
            "name":        ch.get("name", "Unknown"),
            "category":    ch.get("category", "Misc"),
            "points":      ch.get("value") or 0,
            "description": ch.get("description", ""),
            "solved":      ch.get("solved_by_me") or ch.get("solved") or False,
            "files":       files,
            "hints":       [h.get("content","") for h in (ch.get("hints") or [])],
            "instance":    ch.get("connection_info") or "",
            "difficulty":  _difficulty_from_points(ch.get("value") or 0),
        }

    def submit_flag(self, challenge_id, flag: str) -> dict:
        # Need fresh CSRF nonce
        resp = self._req("POST", "/api/v1/challenges/attempt", json={
            "challenge_id": int(challenge_id),
            "submission":   flag.strip(),
        })
        data = resp.json().get("data", {})
        status  = data.get("status", "")
        correct = status == "correct"
        return {"correct": correct, "message": data.get("message", status)}


# ─── HackTheBox ───────────────────────────────────────────────────────────────

class HackTheBox(BasePlatform):
    name     = "htb"
    base_url = "https://www.hackthebox.com"

    def login(self) -> str:
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"
            return "Logged in with API token"

        resp = self._req("POST", "/api/v4/login", json={
            "email":    self.username,
            "password": self.password,
            "remember": True,
        })
        data  = resp.json()
        token = data.get("message", {}).get("access_token") or data.get("access_token")
        if not token:
            raise PlatformError(f"HTB login failed: {data}")
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
        return f"Logged in to HackTheBox as {self.username}"

    def get_challenges(self) -> list:
        resp = self._req("GET", "/api/v4/challenges")
        data = resp.json().get("challenges", [])
        return [self._normalise(ch) for ch in data]

    def _normalise(self, ch: dict) -> dict:
        return {
            "platform_id": str(ch.get("id", "")),
            "name":        ch.get("name", "Unknown"),
            "category":    ch.get("category_name") or ch.get("category", "Misc"),
            "points":      ch.get("points") or 0,
            "description": ch.get("description", ""),
            "solved":      ch.get("solved") or False,
            "files":       [ch["download"]] if ch.get("download") else [],
            "hints":       [],
            "instance":    "",
            "difficulty":  ch.get("difficulty_text", "medium").lower(),
        }

    def submit_flag(self, challenge_id, flag: str) -> dict:
        resp = self._req("POST", f"/api/v4/challenges/{challenge_id}/flag", json={
            "id":   int(challenge_id),
            "flag": flag.strip(),
        })
        data    = resp.json()
        correct = data.get("correct") or data.get("success") or False
        return {"correct": bool(correct), "message": str(data.get("message", data))}


# ─── Manual (no platform, just file organisation) ─────────────────────────────

class ManualPlatform(BasePlatform):
    name = "manual"

    def login(self) -> str:
        return "Manual mode — no platform connected"

    def get_challenges(self) -> list:
        return []

    def submit_flag(self, challenge_id, flag: str) -> dict:
        return {"correct": None, "message": "Manual mode — copy flag and submit on the CTF site"}


# ─── Factory ──────────────────────────────────────────────────────────────────

PLATFORMS = {
    "picoctf": PicoCTF,
    "ctfd":    CTFd,
    "htb":     HackTheBox,
    "manual":  ManualPlatform,
}

def get_platform(config: dict) -> BasePlatform:
    ptype = config.get("type", "manual").lower()
    cls   = PLATFORMS.get(ptype, ManualPlatform)
    return cls(config)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _difficulty_from_points(pts: int) -> str:
    if pts <= 100:  return "easy"
    if pts <= 200:  return "medium"
    if pts <= 350:  return "hard"
    return "insane"


def _import_index_path(base_dir: str, ctf_name: str) -> str:
    root = os.path.join(base_dir, _safe_name(ctf_name))
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, ".import_index.json")


def _load_import_index(base_dir: str, ctf_name: str) -> dict:
    path = _import_index_path(base_dir, ctf_name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_import_index(base_dir: str, ctf_name: str, index_data: dict) -> None:
    path = _import_index_path(base_dir, ctf_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)


def _challenge_key(ch: dict) -> str:
    pid = str(ch.get("platform_id", "") or "").strip()
    if pid:
        return f"pid:{pid}"
    return f"name:{str(ch.get('category','')).strip().lower()}::{str(ch.get('name','')).strip().lower()}"


def _challenge_hash(ch: dict) -> str:
    sig = {
        "name": ch.get("name", ""),
        "category": ch.get("category", ""),
        "points": ch.get("points", 0),
        "description": str(ch.get("description", ""))[:4000],
        "files": ch.get("files", []),
        "hints": ch.get("hints", []),
        "instance": ch.get("instance", ""),
        "solved": bool(ch.get("solved", False)),
    }
    try:
        import hashlib
        raw = json.dumps(sig, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]
    except Exception:
        return str(int(time.time()))


def import_challenges(platform_config: dict, base_dir: str, ctf_name: str, incremental: bool = True) -> dict:
    """
    Full import flow:
    1. Connect to platform
    2. Fetch challenge list
    3. Download files
    4. Create folder structure
    Returns list of challenge dicts ready for the UI.
    """
    if not HAS_REQUESTS:
        return {"error": "requests not installed. Run: pip install requests"}

    results = []
    errors = []
    platform = get_platform(platform_config)
    index_data = _load_import_index(base_dir, ctf_name) if incremental else {}
    new_keys = []
    updated_keys = []

    try:
        login_msg = platform.login()
    except Exception as e:
        return {"error": f"Login failed: {e}"}

    try:
        challenges = platform.get_challenges()
    except Exception as e:
        return {"error": f"Failed to fetch challenges: {e}"}

    for ch in challenges:
        try:
            ckey = _challenge_key(ch)
            chash = _challenge_hash(ch)
            prev = index_data.get(ckey, {}) if isinstance(index_data, dict) else {}
            was_known = bool(prev)
            changed = (not was_known) or (str(prev.get("hash", "")) != chash)

            # Create folder
            safe_cat  = _safe_name(ch["category"])
            safe_name = _safe_name(ch["name"])
            folder    = os.path.join(base_dir, _safe_name(ctf_name), safe_cat, safe_name)
            os.makedirs(os.path.join(folder, "files"), exist_ok=True)

            # Save challenge metadata
            with open(os.path.join(folder, "challenge.json"), "w") as f:
                json.dump(ch, f, indent=2)

            # Download attached files
            downloaded = []
            for url in (ch.get("files") or []):
                try:
                    fname    = url.split("/")[-1].split("?")[0] or "file"
                    dest     = os.path.join(folder, "files", fname)
                    if incremental and os.path.exists(dest) and os.path.getsize(dest) > 0:
                        downloaded.append(dest)
                    else:
                        platform.download_file(url, dest)
                        downloaded.append(dest)
                except Exception as fe:
                    errors.append(f"{ch['name']}: file download failed — {fe}")

            ch["workspace"] = folder
            ch["downloaded_files"] = downloaded
            ch["is_new"] = (not was_known)
            ch["is_updated"] = (was_known and changed)
            results.append(ch)

            if not was_known:
                new_keys.append(ckey)
            elif changed:
                updated_keys.append(ckey)

            if incremental:
                index_data[ckey] = {
                    "hash": chash,
                    "name": ch.get("name", ""),
                    "category": ch.get("category", ""),
                    "workspace": folder,
                    "seen_at": int(time.time()),
                }

        except Exception as e:
            errors.append(f"{ch.get('name','?')}: {e}")

    if incremental:
        try:
            _save_import_index(base_dir, ctf_name, index_data)
        except Exception as e:
            errors.append(f"index save failed: {e}")

    return {
        "login_message": login_msg,
        "challenges":    results,
        "errors":        errors,
        "platform_token": platform.token,  # return for future use
        "new_challenges": [c for c in results if c.get("is_new", False)],
        "updated_challenges": [c for c in results if c.get("is_updated", False)],
        "new_count": len(new_keys),
        "updated_count": len(updated_keys),
    }


def submit_flag_to_platform(platform_config: dict, challenge_id: str, flag: str) -> dict:
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    platform = get_platform(platform_config)
    try:
        platform.login()
        return platform.submit_flag(challenge_id, flag)
    except Exception as e:
        return {"error": str(e)}


def get_challenge_status(platform_config: dict, challenge_id: str) -> dict:
    """Return normalized live status for a challenge id.

    Best-effort, cross-platform shape:
      {"found": bool, "challenge_id": str, "solved": bool, "solve_count": int, "raw": {...}}
    """
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}

    platform = get_platform(platform_config)
    try:
        platform.login()
        rows = platform.get_challenges()
        cid = str(challenge_id or "")
        for ch in rows:
            if str(ch.get("platform_id", "")) != cid:
                continue

            solve_count = 0
            for key in ("solve_count", "solves", "solved_count", "num_solves", "num_solvers"):
                if key in ch:
                    try:
                        solve_count = max(solve_count, int(ch.get(key, 0) or 0))
                    except Exception:
                        pass

            solved = bool(ch.get("solved", False) or ch.get("solved_by_me", False))
            return {
                "found": True,
                "challenge_id": cid,
                "solved": solved,
                "solve_count": solve_count,
                "raw": ch,
            }
        return {"found": False, "challenge_id": cid, "solved": False, "solve_count": 0}
    except Exception as e:
        return {"error": str(e), "found": False, "challenge_id": str(challenge_id or "")}


def _safe_name(s: str) -> str:
    """Convert a string to a safe folder/file name."""
    s = s.strip()
    s = re.sub(r'[<>:"/\\|?*]', "_", s)
    s = re.sub(r'\s+', " ", s)
    return s[:80]
