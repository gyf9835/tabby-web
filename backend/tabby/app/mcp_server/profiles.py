"""Turn the user's synced Tabby config into SSH profile objects.

Handles both encrypted (vault) and plaintext synced configs. Decrypts at most
once per TTL per content to keep PBKDF2 (100k iterations) off the hot path.
"""

import hashlib
import logging
import os
import time

import yaml
from django.conf import settings

from . import vault as vault_crypto

logger = logging.getLogger(__name__)

_cache = {"key": None, "at": 0.0, "value": None}


class WorkspaceError(Exception):
    pass


def _config_for_user(user):
    """Latest config of the user (prefers the active one)."""
    from tabby.app.models import Config

    qs = Config.objects.filter(user=user)
    if user.active_config_id:
        cfg = qs.filter(pk=user.active_config_id).first()
        if cfg:
            return cfg
    return qs.order_by("-modified_at").first()


def load_workspace(user) -> dict:
    """Returns {"profiles": [...], "secrets": {...}, "encrypted": bool,
    "config_name": str} or raises WorkspaceError."""
    cfg = _config_for_user(user)
    if not cfg:
        raise WorkspaceError("no synced config found for this user (sync Tabby first)")

    content = cfg.content or ""
    cache_key = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    pwd = settings.MCP_VAULT_PASSWORD or ""
    cache_key = hashlib.sha256((cache_key + "|" + pwd).encode()).hexdigest()

    now = time.time()
    ttl = settings.MCP_CACHE_TTL
    if _cache["key"] == cache_key and _cache["value"] and now - _cache["at"] < ttl:
        ws = _cache["value"]
        return {
            "profiles": ws["profiles"],
            "secrets": ws["secrets"],
            "encrypted": ws["encrypted"],
            "config_name": cfg.name,
        }

    try:
        data = yaml.safe_load(content)
    except Exception as e:
        raise WorkspaceError(f"synced config is not valid YAML: {e}")

    if not isinstance(data, dict):
        raise WorkspaceError("unexpected synced config format (not a mapping)")

    secrets_map = {}
    if vault_crypto.is_encrypted_config(data):
        if not pwd:
            raise WorkspaceError(
                "synced config is encrypted; set MCP_VAULT_PASSWORD on the "
                "tabby service (or disable config encryption in Tabby settings "
                "and re-sync)"
            )
        try:
            inner = vault_crypto.decrypt_stored_vault(data["vault"], pwd)
        except Exception as e:
            logger.warning("vault decryption failed: %s", e)
            raise WorkspaceError("vault decryption failed (wrong password?)")
        conf = inner.get("config") or {}
        for s in inner.get("secrets") or []:
            key = s.get("key") or {}
            if isinstance(key, dict) and key.get("id"):
                secrets_map[key["id"]] = s
        encrypted = True
    else:
        conf = data
        for s in (data.get("vault") or {}).get("secrets") or []:
            key = s.get("key") or {}
            if isinstance(key, dict) and key.get("id"):
                secrets_map[key["id"]] = s
        encrypted = False

    profiles = []
    for p in conf.get("profiles") or []:
        if not isinstance(p, dict) or p.get("type") != "ssh":
            continue
        profiles.append(p)

    value = {
        "profiles": profiles,
        "secrets": secrets_map,
        "encrypted": encrypted,
    }
    _cache.update({"key": cache_key, "at": now, "value": value})

    return {
        "profiles": profiles,
        "secrets": secrets_map,
        "encrypted": encrypted,
        "config_name": cfg.name,
    }


def resolve_profile(user, server: str) -> dict:
    """Find a profile by name (exact -> case-insensitive) or by id."""
    ws = load_workspace(user)
    profiles = ws["profiles"]
    for p in profiles:
        if server in (p.get("name"), p.get("id")):
            return p
    lower = server.lower()
    matches = [p for p in profiles if str(p.get("name", "")).lower() == lower]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(p.get("name") for p in matches)
        raise WorkspaceError(f"ambiguous server name '{server}': {names}")
    available = ", ".join(sorted(str(p.get("name")) for p in profiles)) or "(none)"
    raise WorkspaceError(f"server '{server}' not found. Available: {available}")


def profile_auth(user, profile: dict) -> dict:
    """Resolve auth material: {"kind": "password"|"key"|"none", "password"/"key": str}"""
    ws = load_workspace(user)
    auth = profile.get("auth")
    if not isinstance(auth, dict) or not auth.get("id"):
        return {"kind": "none"}
    secret = ws["secrets"].get(auth.get("id"))
    if not secret:
        return {"kind": "none"}
    kind = secret.get("type") or auth.get("type") or "password"
    value = secret.get("value")
    if value is None:
        return {"kind": "none"}
    if kind == "key":
        return {"kind": "key", "key": str(value)}
    return {"kind": "password", "password": str(value)}
