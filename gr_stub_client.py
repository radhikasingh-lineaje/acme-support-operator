# Copyright (c) Lineaje, Inc. All rights reserved.
#
# This file is part of the Lineaje AI Policy Orchestration (AIPO) guardrail
# runtime. It is copied alongside instrumented source files so a generated
# guardrail stub can load it via ``_lineaje_load_gr_client()`` and call
# ``enforce()``/``check()`` without any change to the customer's own
# dependencies.
"""Stdlib HTTP client for GR /enforce. Copied into the scanned repo at runtime.

``check(site, payload)`` is the current stub API. ``call_gr_enforce`` remains
for older inserted sites. Both fail open unless the site fail_mode is BLOCK.
Unknown sites are registered and leftover PII is masked locally.

A genuine fail-closed policy block (blocked LLM, CBRN, …) latches for the
rest of this *request* context: later ``check()``/``enforce()`` calls for
*other* sites skip POST /enforce so a processing-note catch cannot keep
extracting files, calling MCP, or dumping document contents. The site that
blocked may still re-POST (model settings can change). The latch is not
process-wide — a blocked chat must not 500 a later GET /chat/jobs poll.
"""
from __future__ import annotations

__version__ = '2.0.0-alpha'

import contextvars
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger("aipo_mcp.gr_stub_client")

_DEFAULT_ENFORCE_TIMEOUT_SEC = 30.0


def _resolve_enforce_timeout_seconds() -> float:
    """How long a single /enforce POST waits before giving up.

    GR_TIMEOUT_MS (milliseconds) overrides the default when set. Previously
    hardcoded to 5.0s with no override — real GR service round trips
    (scanning a slow model's full response, cold-start latency, etc.)
    routinely run 20-30s, so that default caused frequent spurious "read
    operation timed out" failures (each one falling through to fail-open/
    fail-closed per site.fail_mode) under normal, not-actually-broken
    conditions rather than a genuine outage.
    """
    raw = (os.environ.get("GR_TIMEOUT_MS") or "").strip()
    if raw:
        try:
            return max(float(raw) / 1000.0, 0.1)
        except ValueError:
            _logger.warning("GR_TIMEOUT_MS=%r is not a number — using default %.1fs", raw, _DEFAULT_ENFORCE_TIMEOUT_SEC)
    return _DEFAULT_ENFORCE_TIMEOUT_SEC


_RUNTIME_ENV_LOADED = False
_CA_BUNDLE_TRUSTED = False
_MANIFEST_CACHE: dict[str, Any] | None = None
_ACCESS_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_TOKEN_LOCK = threading.Lock()
_TOKEN_SKEW_SEC = 120
# Customer stubs exchange guardrail.json ``refreshtoken`` (a SCIM refresh
# token) here. Identity-service renew cannot decrypt SCIM tokens (HTTP 500
# "trying to decrypt the string") — same rewrite as scripts/gha_repo_scan.py.
_SCIM_RENEW_ACCESS_TOKEN_PATH = "/scim/api/v1/auth/native/renew-access-token"
_IDENTITY_RENEW_ACCESS_TOKEN_PATH = "/lineajeidentity/api/v1/auth/native/renew-access-token"
_DEFAULT_RENEW_ACCESS_TOKEN_URL_DEV = (
    "https://scim-service.commercialdev.dev.veedna.com"
    + _SCIM_RENEW_ACCESS_TOKEN_PATH
)
_DEFAULT_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://scim-service.v2.prod.veedna.com"
    + _SCIM_RENEW_ACCESS_TOKEN_PATH
)
_HARDCODED_GR_ORIGIN_DEV = "https://mcp.commercialdev.dev.veedna.com"
_HARDCODED_GR_ORIGIN_PROD = "https://mcp.v2.prod.veedna.com"


_SITE_REGISTER_ATTEMPTED: set[str] = set()
_SITE_REGISTERED: set[str] = set()
_SITE_POLICY_MAPPINGS: dict[str, list[Any]] = {}
# Request-context latch: a fail-closed policy block on one site must not
# fan out POST /enforce to the remaining insertion points (file_upload,
# mcp_call, tool_to_user, …). Stored as a *mutable object* in a ContextVar
# so ``asyncio.to_thread`` (which copies the context *into* the worker)
# still lets the worker write a block the parent task can see — without a
# process-wide singleton that poisons later HTTP requests (GET /chat/jobs
# after a blocked chat). The blocking site_id may still re-POST.
class _RequestBlockLatch:
    __slots__ = ("payload",)

    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None


_PROCESS_BLOCK_LATCH: contextvars.ContextVar[_RequestBlockLatch | None] = contextvars.ContextVar(
    "gr_process_block_latch", default=None,
)


def _ensure_request_latch() -> _RequestBlockLatch:
    """Create the per-request latch on the current context if missing.

    Inserted stubs construct ``SiteDescriptor`` on the event-loop thread
    *before* ``asyncio.to_thread(enforce)``, so the same latch object is
    what the worker inherits and mutates.
    """
    latch = _PROCESS_BLOCK_LATCH.get()
    if latch is None:
        latch = _RequestBlockLatch()
        _PROCESS_BLOCK_LATCH.set(latch)
    return latch


def _reset_runtime_caches() -> None:
    """Test helper — drop manifest / access-token / site-register caches."""
    global _RUNTIME_ENV_LOADED, _CA_BUNDLE_TRUSTED, _MANIFEST_CACHE
    _RUNTIME_ENV_LOADED = False
    _CA_BUNDLE_TRUSTED = False
    _MANIFEST_CACHE = None
    _ACCESS_TOKEN_CACHE.clear()
    _SITE_REGISTER_ATTEMPTED.clear()
    _SITE_REGISTERED.clear()
    _SITE_POLICY_MAPPINGS.clear()
    _PROCESS_BLOCK_LATCH.set(None)


def _record_process_block(site_id: str, warning: str, policy_id: str = "") -> None:
    """Latch a genuine fail-closed block so later sites skip POST /enforce."""
    latch = _ensure_request_latch()
    if latch.payload is None:
        latch.payload = {
            "site_id": site_id or "",
            "warning": warning or "Request denied by policy enforcement.",
            "policy_id": policy_id or "",
        }


def _current_process_block() -> dict[str, Any] | None:
    latch = _PROCESS_BLOCK_LATCH.get()
    if latch is None:
        return None
    return latch.payload


def _process_block_for_other_site(site_id: str) -> dict[str, Any] | None:
    """Prior block, unless this is the same site_id re-checking."""
    prior = _current_process_block()
    if not prior:
        return None
    blocked_site = str(prior.get("site_id") or "")
    this_site = site_id or ""
    if this_site and blocked_site and this_site == blocked_site:
        return None
    return prior


def _policy_id_from_decision(decision: "Decision") -> str:
    actions = decision.actions_applied or []
    if actions and isinstance(actions[0], dict):
        return str(actions[0].get("policy_id") or "")
    return ""


def _maybe_record_process_block(decision: "Decision", site: "SiteDescriptor") -> None:
    """Record only a live policy block — not an infra/outage fail-closed."""
    if not decision.blocked or getattr(decision, "infra_failure", False):
        return
    _record_process_block(
        getattr(site, "site_id", "") or "",
        decision.warning or "",
        _policy_id_from_decision(decision),
    )


def _skipped_other_site_decision(
    site: "SiteDescriptor", payload: Any, prior: dict[str, Any],
) -> "Decision":
    """Fail-closed locally without POSTing — prior site already blocked."""
    hop = f"site_id={site.site_id}" if getattr(site, "site_id", "") else "site_id=<unknown>"
    reason = prior.get("warning") or "Request denied by policy enforcement."
    policy_id = prior.get("policy_id") or "prior_block"
    _logger.warning(
        "gr_stub_client.check[%s]: skipping POST /enforce — request already "
        "blocked at site_id=%s (%s)",
        hop, prior.get("site_id") or "<unknown>", reason,
    )
    _announce_enforce(
        "-", hop, "block",
        extra=f"skipped — prior policy block at site_id={prior.get('site_id') or '<unknown>'}",
    )
    return Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{"policy_id": policy_id, "action": "block"}],
        "recommendations": [],
        "warning": reason,
    }, site_id=getattr(site, "site_id", "") or "")


def _guardrail_manifest_candidates() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    candidates = [
        os.path.join(here, ".lineaje", "guardrail.json"),
        os.path.join(cwd, ".lineaje", "guardrail.json"),
    ]
    # Walk parents so a nested source file can still find repo-root manifest.
    cur = here
    for _ in range(6):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        candidates.append(os.path.join(parent, ".lineaje", "guardrail.json"))
        cur = parent
    return candidates


def _load_guardrail_manifest() -> dict[str, Any]:
    """Load ``.lineaje/guardrail.json`` (written by GHA PRs / MCP workflow)."""
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is not None:
        return _MANIFEST_CACHE
    for path in _guardrail_manifest_candidates():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                _MANIFEST_CACHE = data
                return data
        except (OSError, ValueError, TypeError):
            continue
    _MANIFEST_CACHE = {}
    return _MANIFEST_CACHE


def _origin_for_enforce_api(url: str) -> str:
    """Strip a trailing ``/mcp`` or ``/enforce`` path so callers can POST
    ``/enforce`` without doubling it up.

    Combined MCP+GR serves the guardrail at the server root. A scan that
    recorded the MCP endpoint (``http://host:8000/mcp``) as GR_SERVICE_URL
    would otherwise miss the handler entirely. GR_SERVICE_URL is also written
    with the ``/enforce`` path already spelled out (customer-facing
    ``.env.example`` files show the actual endpoint) — stripping it here
    keeps both forms equivalent.
    """
    s = (url or "").strip()
    if " #" in s:
        s = s.split(" #", 1)[0].strip()
    s = s.rstrip("/")
    if s.lower().endswith("/mcp"):
        s = s[: -len("/mcp")].rstrip("/")
    elif s.lower().endswith("/enforce"):
        s = s[: -len("/enforce")].rstrip("/")
    return s


def _is_loopback_origin(origin: str) -> bool:
    u = (origin or "").lower()
    return any(marker in u for marker in ("127.0.0.1", "localhost", "::1"))


def _is_prod_env() -> bool:
    """Active-env check shared by every hardcoded dev/prod default in this file
    (GR origin, identity/SCIM renew URL) — same signals mcp_server.py's
    DEPLOYMENT_ENV resolution uses, so this customer-side stub and the server
    that generated its manifest never disagree about which environment is live."""
    manifest_url = str(_load_guardrail_manifest().get("gr_service_url") or "")
    blob = " ".join(
        (
            os.environ.get("GR_SERVICE_URL", ""),
            os.environ.get("MCP_SERVER_URL", ""),
            os.environ.get("DEPLOYMENT_ENV", ""),
            os.environ.get("LOGGER_ENV", ""),
            manifest_url,
        )
    ).lower()
    dep = (os.environ.get("DEPLOYMENT_ENV") or os.environ.get("LOGGER_ENV") or "").strip().lower()
    return "v2.prod.veedna.com" in blob or dep in ("prod", "production", "prd")


def _hardcoded_gr_origin() -> str:
    """Hosted GR origin for the active env: prod -> v2.prod, otherwise commercialdev."""
    return _HARDCODED_GR_ORIGIN_PROD if _is_prod_env() else _HARDCODED_GR_ORIGIN_DEV


def _default_renew_access_token_url() -> str:
    """Hosted SCIM renew-access-token URL for the active env: prod -> v2.prod,
    otherwise commercialdev. Same dev/prod signal as _hardcoded_gr_origin."""
    return _DEFAULT_RENEW_ACCESS_TOKEN_URL_PROD if _is_prod_env() else _DEFAULT_RENEW_ACCESS_TOKEN_URL_DEV


def _load_guardrail_manifest_url() -> str:
    """Enforce origin from ``.lineaje/guardrail.json`` (no ``/mcp`` suffix)."""
    return _origin_for_enforce_api(_load_guardrail_manifest().get("gr_service_url") or "")


def _resolve_gr_origin(explicit: str | None = None) -> str:
    """POST /enforce to the hosted GR origin for the active environment.

    Prefers an explicit non-loopback origin (unit tests), then the
    ``.lineaje/guardrail.json`` manifest's ``gr_service_url`` (written by the
    MCP scan for this environment), then ``GR_SERVICE_URL``. Loopback,
    missing, or unusable values fall back to the hardcoded hosted origin for
    the active env — a local ``GR_SERVICE_URL=http://127.0.0.1:8000`` must
    not become the enforce origin (connection-refused fail-open).
    """
    try:
        _ensure_runtime_env_loaded()
        for candidate in (
            _origin_for_enforce_api(explicit or ""),
            _load_guardrail_manifest_url(),
            _origin_for_enforce_api(os.environ.get("GR_SERVICE_URL", "")),
        ):
            if candidate and not _is_loopback_origin(candidate):
                return candidate
        return _hardcoded_gr_origin()
    except Exception:
        return _hardcoded_gr_origin()


def _looks_like_jwt(value: str) -> bool:
    s = (value or "").strip()
    return s.count(".") == 2 and s.startswith("eyJ")


def _scim_renew_url(url: str) -> str:
    """Map identity-service renew URLs onto SCIM. SCIM-issued refresh tokens
    fail at identity with HTTP 500 ``trying to decrypt the string``."""
    u = (url or "").strip().rstrip("/")
    if not u or _IDENTITY_RENEW_ACCESS_TOKEN_PATH not in u:
        return u
    parsed = urllib.parse.urlparse(u)
    host = (parsed.netloc or "").replace("lineaje-identity-service", "scim-service")
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}{_SCIM_RENEW_ACCESS_TOKEN_PATH}"


def _parse_access_token(raw_text: str) -> str:
    text = (raw_text or "").strip()
    if not text:
        return ""
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        return text if _looks_like_jwt(text) else ""
    if isinstance(parsed, str):
        return parsed.strip()
    if isinstance(parsed, dict):
        return (parsed.get("access_token") or "").strip()
    return ""


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        import base64
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _jwt_exp_epoch(token: str) -> float:
    exp = _jwt_payload(token).get("exp")
    if isinstance(exp, (int, float)):
        return float(exp)
    return time.time() + 3600.0


def _tenant_id_from_bearer(pat: str, fallback: str = "") -> str:
    """Tenant for site-manifest register — same identity /enforce binds to."""
    explicit = (fallback or "").strip()
    if explicit:
        return explicit
    claims = _jwt_payload(pat)
    meta = claims.get("user_metadata") if isinstance(claims.get("user_metadata"), dict) else {}
    for key in ("tenant_id",):
        for src in (claims, meta):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return (os.environ.get("GR_TENANT_ID") or "").strip()


def _exchange_refresh_for_access(refresh_token: str, renew_url: str) -> str:
    """POST renew-access-token?refreshToken=… → short-lived access JWT. Empty on failure."""
    if not refresh_token or not renew_url:
        return ""
    key = refresh_token
    now = time.time()
    cached = _ACCESS_TOKEN_CACHE.get(key)
    if cached is not None:
        access, deadline = cached
        if access and now < deadline - _TOKEN_SKEW_SEC:
            return access
    q = urllib.parse.urlencode({"refreshToken": refresh_token})
    req = urllib.request.Request(
        f"{renew_url.rstrip('/')}?{q}",
        data=b"null",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            access = _parse_access_token(resp.read().decode())
    except Exception as exc:
        _logger.warning("refresh-token exchange failed (%s) — using refresh token as Bearer", exc)
        return ""
    if not access:
        return ""
    _ACCESS_TOKEN_CACHE[key] = (access, _jwt_exp_epoch(access))
    return access


def _looks_like_lineaje_pat(value: str) -> bool:
    return (value or "").strip().startswith("lineaje_pat")


def _usable_scim_refresh_token(raw: str) -> str:
    """Opaque SCIM refresh token only — never a JWT, URL, or identity PAT."""
    s = (raw or "").strip()
    if not s or s.startswith("http"):
        return ""
    if _looks_like_jwt(s) or _looks_like_lineaje_pat(s):
        return ""
    return s


def _strip_bearer_prefix(value: str) -> str:
    raw = (value or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def _mcp_access_jwt_from_env() -> str:
    """Access JWT the MCP server already has (session / local-dev env)."""
    for key in (
        "MCP_BEARER_TOKEN",
        "LINEAJE_BEARER_TOKEN",
        "GR_BEARER_TOKEN",
        "BEARER_TOKEN",
    ):
        token = _strip_bearer_prefix(os.environ.get(key, ""))
        if token and _looks_like_jwt(token):
            return token
    return ""


def _pat_candidate(raw: str) -> str:
    """A ``lineaje_pat_…`` credential, verbatim — never a JWT or refresh blob.

    Used as a last-resort Bearer: POST /enforce exchanges a Lineaje PAT
    server-side (see mcp_server.py's ``_admin_http_bearer`` comment — only
    /admin/site-manifest/register requires a real access JWT up front).
    """
    s = (raw or "").strip()
    return s if _looks_like_lineaje_pat(s) else ""


def _resolve_enforce_bearer(lineaje_pat: str = "") -> str:
    """Return the Authorization Bearer for POST /enforce.

    Prefer an access JWT the MCP server already has. Otherwise take a SCIM
    refresh token (``LINEAJE_REFRESH_TOKEN`` / ``.lineaje/guardrail.json``
    ``refreshtoken``) and exchange it at SCIM renew-access-token. Identity-service
    renew URLs are rewritten to SCIM (identity cannot decrypt SCIM refresh
    tokens). If the exchange cannot run, the refresh token itself is sent so
    ``POST /enforce`` can exchange it server-side.

    A scan-operator ``LINEAJE_PAT_TOKEN=lineaje_pat_…`` in a local ``.env``
    must not win over the customer refresh token — that PAT is a different
    identity and skips the renew path on /enforce.

    When no genuine SCIM refresh token is available anywhere (the common MCP/
    IDE-scan case: ``.lineaje/guardrail.json``'s ``refreshtoken`` holds the
    ``unifai-runtime`` PAT minted by ``inject_runtime_pat_into_manifest_json``
    instead), fall back to that ``lineaje_pat_…`` value directly as the
    Bearer — /enforce exchanges it server-side. Without this fallback,
    ``_usable_scim_refresh_token`` discards every PAT-shaped candidate and
    this function returns "", so /enforce is called unauthenticated and
    fails open silently.
    """
    explicit = _strip_bearer_prefix(lineaje_pat)
    if explicit and _looks_like_jwt(explicit):
        return explicit

    mcp_jwt = _mcp_access_jwt_from_env()
    if mcp_jwt:
        return mcp_jwt

    manifest = _load_guardrail_manifest()
    refresh = (
        _usable_scim_refresh_token(os.environ.get("LINEAJE_REFRESH_TOKEN") or "")
        or _usable_scim_refresh_token(os.environ.get("MCP_REFRESH_TOKEN") or "")
        or _usable_scim_refresh_token(str(manifest.get("refreshtoken") or ""))
        or _usable_scim_refresh_token(str(manifest.get("refresh_token") or ""))
        or _usable_scim_refresh_token(explicit)
        or _usable_scim_refresh_token(os.environ.get("LINEAJE_PAT_TOKEN") or "")
        or _usable_scim_refresh_token(os.environ.get("LINEAJE_PAT") or "")
    )

    if not refresh:
        env_pat = (
            os.environ.get("LINEAJE_PAT_TOKEN")
            or os.environ.get("LINEAJE_PAT")
            or ""
        ).strip()
        if env_pat and _looks_like_jwt(env_pat):
            return env_pat
        if explicit and _looks_like_jwt(explicit):
            return explicit
        # Same priority order as the genuine-refresh-token search above: the
        # customer's own manifest-embedded PAT wins over a scan-operator's
        # local-env PAT.
        return (
            _pat_candidate(str(manifest.get("refreshtoken") or ""))
            or _pat_candidate(str(manifest.get("refresh_token") or ""))
            or _pat_candidate(explicit)
            or _pat_candidate(os.environ.get("LINEAJE_PAT_TOKEN") or "")
            or _pat_candidate(os.environ.get("LINEAJE_PAT") or "")
        )

    raw_renew = (
        (os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL") or "").strip()
        or (manifest.get("renew_access_token_url") or "").strip()
        or _default_renew_access_token_url()
    )
    renew_url = _scim_renew_url(raw_renew) or raw_renew
    with _TOKEN_LOCK:
        access = _exchange_refresh_for_access(refresh, renew_url)
    return access or refresh


def _ca_bundle_candidates() -> list[str]:
    """Same walk-parents search as _guardrail_manifest_candidates(), for a
    customer-provided ``.lineaje/ca-bundle.pem`` instead of guardrail.json."""
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    candidates = [
        os.path.join(here, ".lineaje", "ca-bundle.pem"),
        os.path.join(cwd, ".lineaje", "ca-bundle.pem"),
    ]
    cur = here
    for _ in range(6):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        candidates.append(os.path.join(parent, ".lineaje", "ca-bundle.pem"))
        cur = parent
    return candidates


def _ensure_ca_bundle_trusted() -> None:
    """Trust a self-hosted GR/MCP server's TLS cert without any change to
    the customer's own app entrypoint.

    A GR/MCP server fronted by Caddy (the common self-hosted-VM deployment)
    serves TLS off a self-signed local CA, not a public one — every request
    fails ``CERTIFICATE_VERIFY_FAILED: unable to get local issuer
    certificate`` until that CA is trusted. Python's urllib re-reads
    SSL_CERT_FILE/SSL_CERT_DIR (via ssl.get_default_verify_paths()) each
    time it builds a default SSLContext, so setting it here — right before
    this module's first request, not at interpreter startup — is enough;
    the customer's app never needs its own CA-bundle-loading code. See
    ``.env.example`` for the one-time steps to produce this file.
    Never overrides an SSL_CERT_FILE/REQUESTS_CA_BUNDLE the customer already
    set themselves. Cached — cheap to call from every function that issues
    a request, so each of them gets this without depending on call order.
    """
    global _CA_BUNDLE_TRUSTED
    if _CA_BUNDLE_TRUSTED:
        return
    _CA_BUNDLE_TRUSTED = True
    for path in _ca_bundle_candidates():
        if not os.path.isfile(path):
            continue
        os.environ.setdefault("SSL_CERT_FILE", path)
        os.environ.setdefault("REQUESTS_CA_BUNDLE", path)
        return


def _ensure_runtime_env_loaded() -> None:
    """Load GR_SERVICE_URL / PAT from a nearby .env or .lineaje/guardrail.json."""
    global _RUNTIME_ENV_LOADED
    if _RUNTIME_ENV_LOADED:
        return
    _RUNTIME_ENV_LOADED = True
    _ensure_ca_bundle_trusted()
    _keys = frozenset({
        "GR_SERVICE_URL", "LINEAJE_PAT_TOKEN", "LINEAJE_PAT", "GR_BEARER_TOKEN",
        "LINEAJE_REFRESH_TOKEN", "MCP_REFRESH_TOKEN", "LINEAJE_RENEW_ACCESS_TOKEN_URL",
        "MCP_BEARER_TOKEN", "LINEAJE_BEARER_TOKEN", "BEARER_TOKEN",
    })
    _candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]
    for path in _candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    key, _, val = stripped.partition("=")
                    key = key.strip()
                    if key in _keys and key not in os.environ:
                        os.environ[key] = val.strip().strip('"').strip("'")
        except OSError:
            pass
        break


def call_gr_enforce(
    data: Any,
    source_type: str,
    destination_type: str,
    lineaje_pat: str = "",
    gr_service_url: str | None = None,
    violations: list[dict] | None = None,
    enabled_policies: list[str] | None = None,
    candidate_policies: list[str] | None = None,
    site_id: str | None = None,
    tenant_id: str = "",
    timeout: "float | None" = None,
) -> dict[str, Any]:
    """POST /enforce. Fail-open on errors; 403 is a real block."""
    if destination_type == "skill_check" and _looks_like_quarantined_skill_path(data):
        _logger.warning(
            "gr_stub_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called",
            f"{source_type}->{destination_type}",
        )
        return {
            "status": "block",
            "result": {"data": data},
            "actions_applied": [{
                "policy_id": "AI_SKILL_SEC_001",
                "action": "deny_execute",
                "deny_execute": True,
            }],
            "recommendations": [],
            "warning": _DANGEROUS_SKILL_LOAD_NOTE,
        }
    if timeout is None:
        timeout = _resolve_enforce_timeout_seconds()
    url = _resolve_gr_origin(gr_service_url)
    if not url:
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": "GR_SERVICE_URL not configured — guardrail skipped (fail-open)",
        }

    hop = f"{source_type}->{destination_type}"
    if site_id:
        hop = f"{hop} site_id={site_id}"
    prior = _process_block_for_other_site(site_id or "")
    if prior is not None:
        reason = prior.get("warning") or "Request denied by policy enforcement."
        policy_id = prior.get("policy_id") or "prior_block"
        _logger.warning(
            "gr_stub_client[%s]: skipping POST /enforce — request already "
            "blocked at site_id=%s (%s)",
            hop, prior.get("site_id") or "<unknown>", reason,
        )
        return {
            "status": "block",
            "result": {"data": data},
            "actions_applied": [{"policy_id": policy_id, "action": "block"}],
            "recommendations": [],
            "warning": reason,
        }

    pat = _resolve_enforce_bearer(lineaje_pat)
    params_key = "out_params" if destination_type == "agent" else "in_params"

    body: dict[str, Any] = {
        "source_type": source_type,
        "destination_type": destination_type,
        params_key: {"data": _jsonable_payload(data)},
    }
    if violations:
        body["violations"] = violations
    if enabled_policies:
        body["enabled_policies"] = enabled_policies
    if candidate_policies:
        body["candidate_policies"] = candidate_policies
    if site_id:
        body["site_id"] = site_id
    if tenant_id:
        body["tenant_id"] = tenant_id

    req = urllib.request.Request(
        f"{url}/enforce",
        data=json.dumps(body, default=_json_default).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {pat}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
        if result.get("status") == "escalate":
            _logger.warning("gr_stub_client[%s]: escalation flagged — passing through for human review", hop)
        _announce_enforce(url, hop, result.get("status", "allow"), extra=f"actions={result.get('actions_applied') or []}")
        if result.get("status") == "block":
            actions = result.get("actions_applied") or []
            pid = ""
            if actions and isinstance(actions[0], dict):
                pid = str(actions[0].get("policy_id") or "")
            _record_process_block(site_id or "", result.get("warning") or "", pid)
        return result
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0].get("policy_id", "unknown") if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_stub_client[%s]: BLOCKED by policy=%s — %s", hop, policy_id, reason)
            _record_process_block(site_id or "", reason, policy_id)
            return {
                "status": "block",
                "result": {"data": data},
                "actions_applied": [{"policy_id": policy_id, "action": "block"}],
                "recommendations": [],
                "warning": reason,
            }
        _logger.warning(
            "gr_stub_client[%s]: GR service call failed (%s) POST %s/enforce — failing open",
            hop, exc, url,
        )
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": f"GR service error: {exc}",
        }
    except Exception as exc:
        _logger.warning(
            "gr_stub_client[%s]: GR service call failed (%s) POST %s/enforce — failing open",
            hop, exc, url,
        )
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": f"GR service unreachable: {exc}",
        }



_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _new_ulid() -> str:
    """26-char Crockford ULID (48-bit timestamp + 80-bit randomness)."""
    import os as _os
    import time as _time

    ts_ms = int(_time.time() * 1000) & 0xFFFFFFFFFFFF  # 48 bits
    rand = int.from_bytes(_os.urandom(10), "big")  # 80 bits
    value = (ts_ms << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


@dataclass
class SiteDescriptor:
    """Scan-time facts for one call site. ``fail_mode`` is ALLOW_WITH_AUDIT or BLOCK."""
    site_id: str
    phase: str = ""
    boundary: dict = field(default_factory=dict)
    components: dict = field(default_factory=dict)
    candidate_policies: "list[dict]" = field(default_factory=list)
    site_manifest_version: "str | None" = None
    fail_mode: str = "ALLOW_WITH_AUDIT"
    source_type: str = ""
    destination_type: str = ""

    def __post_init__(self) -> None:
        # Bind the per-request latch on the constructing thread (the FastAPI
        # handler) before asyncio.to_thread copies the context into a worker.
        _ensure_request_latch()


_PHASE_BOUNDARY_TO_SOURCE_DEST: dict[tuple[str, str, str], tuple[str, str]] = {
    ("pre_model", "agent_message", "model"): ("agent", "llm"),
    ("pre_model", "user_interface", "model"): ("user_interface", "llm"),
    ("post_model", "model", "agent_message"): ("llm", "agent"),
    ("pre_agent_send", "agent_message", "agent_message"): ("agent", "agent"),
    ("post_agent_receive", "user_interface", "agent_message"): ("user_interface", "agent"),
    ("post_tool", "database", "agent_message"): ("database", "agent"),
    ("post_tool", "external_endpoint", "agent_message"): ("api", "agent"),
    ("post_tool", "tool_result", "agent_message"): ("agent", "tool"),
    ("pre_tool", "agent_message", "tool_result"): ("agent", "tool"),
    ("pre_tool", "user_interface", "tool_result"): ("user_interface", "tool"),
    ("data_egress", "model", "user_interface"): ("llm", "user_interface"),
    ("data_egress", "agent_message", "user_interface"): ("agent", "user_interface"),
    ("data_egress", "agent_message", "external_endpoint"): ("agent", "external"),
    ("data_egress", "tool_result", "user_interface"): ("tool", "user_interface"),
    ("data_egress", "html", "user_interface"): ("html", "user_interface"),
    ("security_decision", "agent_message", "agent_message"): ("agent", "policy_engine"),
    ("log_emit", "log", "log"): ("agent", "log"),
}


def _source_dest_from_site(site: "SiteDescriptor") -> tuple[str, str]:
    src = getattr(site, "source_type", "") or ""
    dst = getattr(site, "destination_type", "") or ""
    if src and dst:
        return src, dst
    boundary = getattr(site, "boundary", None) or {}
    return _PHASE_BOUNDARY_TO_SOURCE_DEST.get(
        (getattr(site, "phase", "") or "", boundary.get("source") or "", boundary.get("sink") or ""),
        ("", ""),
    )


_DANGEROUS_SKILL_LOAD_NOTE = "This skill is dangerous to be loaded."
_QUARANTINED_SKILL_PATH_KEYS = (
    "skill_path", "skill_file", "path", "file_path", "data",
    "skill_manifest_path", "manifest_path",
)
_LIVE_SKILL_BASENAMES = frozenset({"skill.md", "skills.md"})
_BLOCKED_SKILL_BASENAMES = frozenset({
    "skill.md.blocked", "skills.md.blocked",
})


def _looks_like_quarantined_skill_path(value: Any) -> bool:
    """True when *value* names a ``SKILL.md.blocked`` file (or live sibling)."""
    if isinstance(value, dict):
        return any(
            _looks_like_quarantined_skill_path(value.get(k))
            for k in _QUARANTINED_SKILL_PATH_KEYS
        )
    if isinstance(value, (list, tuple)):
        return any(_looks_like_quarantined_skill_path(item) for item in value)
    raw = str(value or "").strip()
    if not raw:
        return False
    base = raw.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith(".md.blocked") or base in _BLOCKED_SKILL_BASENAMES:
        return True
    try:
        if base in _LIVE_SKILL_BASENAMES and os.path.isfile(raw + ".blocked"):
            return True
        if os.path.isdir(raw):
            for name in ("SKILL.md.blocked", "skills.md.blocked", "skill.md.blocked"):
                if os.path.isfile(os.path.join(raw, name)):
                    return True
    except OSError:
        return False
    return False


def _site_is_skill_check(site: "SiteDescriptor") -> bool:
    phase = (getattr(site, "phase", "") or "").strip()
    _src, dst = _source_dest_from_site(site)
    return phase == "skill_check" or dst == "skill_check"


def _local_quarantined_skill_decision(site: "SiteDescriptor", payload: Any) -> "Decision | None":
    """Refuse a scan-quarantined skill on customer disk without POSTing /enforce.

    ``block_malicious_skills`` already renamed SKILL.md → SKILL.md.blocked.
    Hosted GR cannot see that file; this is the same local refuse the inline
    ``gr_check`` helper uses so the agent cannot keep invoking the skill.
    Site-local — does not latch the request-wide process block (job poll).
    """
    if not _site_is_skill_check(site):
        return None
    if not _looks_like_quarantined_skill_path(payload):
        return None
    hop = f"site_id={site.site_id}" if getattr(site, "site_id", "") else "site_id=<unknown>"
    _logger.warning(
        "gr_stub_client.check[%s]: quarantined skill (*.blocked) — not loaded, GR not called",
        hop,
    )
    return Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{
            "policy_id": "AI_SKILL_SEC_001",
            "action": "deny_execute",
            "deny_execute": True,
        }],
        "recommendations": [],
        "warning": _DANGEROUS_SKILL_LOAD_NOTE,
    }, site_id=getattr(site, "site_id", "") or "")


def _stub_must_not_crash_host(site: "SiteDescriptor") -> bool:
    """Leftover log/UI stubs sit on FastAPI handlers; raising is a 500.

    Only explicit log/user_interface destinations qualify. Do not infer from
    a leftover ``phase=data_egress`` default — LLM sites in tests (and any
    mis-tagged pre_model hop) must still raise.
    """
    src, dst = _source_dest_from_site(site)
    if dst == "llm" or src == "llm":
        return False
    explicit = (getattr(site, "destination_type", None) or "").strip()
    if explicit in ("log", "user_interface"):
        return True
    phase = (getattr(site, "phase", None) or "").strip()
    return phase == "log_emit"


def _payload_after_host_safe_block(
    site: "SiteDescriptor", decision: "Decision", original: Any,
) -> Any:
    """Keep HTTP/log handlers alive after a policy block.

    Log lines stay as-is (the logger still runs). JSON job/error dicts gain
    ``policy_error`` so a UI poll can render the block instead of 500.
    """
    _src, dst = _source_dest_from_site(site)
    phase = (getattr(site, "phase", None) or "").strip()
    if dst == "log" or phase == "log_emit":
        return original
    warning = (decision.warning or "Request blocked by guardrail policy").strip()
    if isinstance(original, dict):
        out = dict(original)
        out.setdefault("status", "error")
        out.setdefault("detail", warning)
        out["policy_error"] = {"type": "guardrail", "message": warning}
        return out
    return original


class GuardrailUnavailableError(PermissionError):
    """Raised instead of ``PermissionError`` when a BLOCK-mode site fails
    CLOSED because the GR service itself couldn't be reached/consulted
    (unreachable, misconfigured, errored) — never because a live decision
    actually found a violation. A ``PermissionError`` that is NOT this
    subclass always means a real policy verdict.

    Callers (including generated stub call sites — see
    guardrail_stub_insertion.py's ``_make_check_stub_line``) can catch this
    specifically to fail OPEN (pass the original value through) on a GR
    outage, without weakening the fail-closed guarantee for genuine blocks.
    """


class Decision:
    """Result of ``check()``. Use ``blocked`` / ``payload`` / ``as_error()``."""

    def __init__(self, raw: dict, *, site_id: str = ""):
        self.raw = raw
        self.site_id = site_id
        self.status = raw.get("status", "allow")
        self.verdict = raw.get("verdict") or self.status.upper()
        self.result = raw.get("result") or {}
        self.payload = self.result.get("data")
        self.actions_applied = raw.get("actions_applied", [])
        self.recommendations = raw.get("recommendations", [])
        self.warning = raw.get("warning")
        self.infra_failure = bool(raw.get("infra_failure"))

    @property
    def blocked(self) -> bool:
        return self.status == "block"

    def as_error(self) -> PermissionError:
        """PermissionError (or GuardrailUnavailableError — see its docstring)
        for a policy block. ``check()`` never raises this itself.

        The message is always prefixed with ``Request blocked by guardrail
        policy:`` so customer agent code can fail closed (stop file
        extraction, MCP/tool calls, and document dumps) instead of treating
        the block as a normal model reply / processing note.
        """
        site_note = f" at site {self.site_id}" if self.site_id else ""
        message = (self.warning or f"blocked by guardrail policy{site_note}").strip()
        if not message.lower().startswith("request blocked by guardrail"):
            message = f"Request blocked by guardrail policy: {message}"
        if self.infra_failure:
            return GuardrailUnavailableError(message)
        return PermissionError(message)


_PII_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.I), "[REDACTED_EMAIL]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    ("cc", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CC]"),
    (
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
        "[REDACTED_PHONE]",
    ),
)


def _mask_pii_text(text: str) -> tuple[str, int]:
    hits = 0
    out = text
    for _kind, pat, repl in _PII_PATTERNS:
        out, n = pat.subn(repl, out)
        hits += n
    return out, hits


def _mask_pii_tree(value: Any) -> tuple[Any, int]:
    """Stdlib PII mask so GR miss / unknown_site cannot leak raw identifiers."""
    if isinstance(value, str):
        return _mask_pii_text(value)
    if isinstance(value, dict):
        total = 0
        rebuilt: dict[str, Any] = {}
        for k, v in value.items():
            nv, n = _mask_pii_tree(v)
            rebuilt[k] = nv
            total += n
        return rebuilt, total
    if isinstance(value, list):
        total = 0
        rebuilt_l: list[Any] = []
        for v in value:
            nv, n = _mask_pii_tree(v)
            rebuilt_l.append(nv)
            total += n
        return rebuilt_l, total
    if isinstance(value, tuple):
        items = []
        total = 0
        for v in value:
            nv, n = _mask_pii_tree(v)
            items.append(nv)
            total += n
        return tuple(items), total
    data = getattr(value, "data", None)
    if isinstance(value, urllib.request.Request) or (
        type(value).__name__ == "Request" and data is not None
    ):
        text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data or "")
        masked, n = _mask_pii_text(text)
        if n:
            try:
                value.data = masked.encode("utf-8")
            except Exception:
                pass
        return value, n
    page = getattr(value, "page_content", None)
    if isinstance(page, str):
        masked, n = _mask_pii_text(page)
        if n:
            try:
                value.page_content = masked
            except Exception:
                pass
        return value, n
    return value, 0


def _fail_response(site: "SiteDescriptor", warning: str, payload: Any) -> dict:
    """Unreachable GR / unresolved unknown_site: mask PII; otherwise fail open.

    Do not fail-closed here — leftover ALLOW_WITH_AUDIT stubs raise
    PermissionError on ``blocked`` and that kills the customer app.
    """
    masked, n = _mask_pii_tree(payload)
    if n:
        return {
            "status": "mask",
            "result": {"data": masked},
            "actions_applied": [{"policy_id": "AI_DAT_SEC_012", "action": "mask", "count": n}],
            "recommendations": [],
            "warning": f"{warning} — local PII mask ({n} hit(s))",
        }
    if getattr(site, "fail_mode", None) == "BLOCK" and "unknown_site" not in warning.lower():
        return {
            "status": "block",
            "result": {"data": payload},
            "actions_applied": [],
            "recommendations": [],
            "warning": f"{warning} — failing CLOSED (site fail_mode=BLOCK)",
            "infra_failure": True,
        }
    return {
        "status": "allow",
        "result": {"data": payload},
        "actions_applied": [],
        "recommendations": [],
        "warning": warning,
    }


def _find_assignment_line(lines: list[str], var_name: str, before_line: int) -> int | None:
    """1-based line of ``var_name = ...`` assignment strictly before ``before_line``."""
    pat = re.compile(
        rf"^\s*(?:[A-Za-z_][\w.<>\[\],\s]*\s+)?{re.escape(var_name)}\s*(?::=|=)(?!=)\s*(?:f|[(\"']|\"\"\"|''')"
    )
    upper = min(max(before_line - 1, 0), len(lines))
    for i in range(upper - 1, -1, -1):
        if pat.match(lines[i]):
            return i + 1
    return None


def _assignment_stmt_span(lines: list[str], assign_line: int) -> tuple[int, int] | None:
    """0-based inclusive (start, end) line indices for a multi-line assignment."""
    import ast as _ast

    start = assign_line - 1
    if start < 0 or start >= len(lines):
        return None
    for end in range(start, min(start + 60, len(lines))):
        block = "".join(lines[start : end + 1])
        try:
            mod = _ast.parse(f"def __lineaje_fn():\n{block}\n")
        except SyntaxError:
            continue
        body = mod.body[0].body  # type: ignore[attr-defined]
        if not body or not isinstance(body[0], _ast.Assign):
            continue
        stmt = body[0]
        stmt_end = getattr(stmt, "end_lineno", None)
        if stmt_end is None:
            return start, end
        end_idx = start + max(0, stmt_end - 2)
        return start, min(end_idx, len(lines) - 1)
    return None


def _decode_body(raw: Any) -> Any:
    """Bytes/str body → parsed JSON if possible, else unicode text."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except ValueError:
            return text
    return raw


_MAX_INLINE_FILE_BYTES = 512 * 1024
_MAX_INLINE_FILES = 8
_MAX_JSONABLE_DEPTH = 8
_PATH_TYPE_NAMES = frozenset({"Path", "PosixPath", "WindowsPath", "PurePath", "PurePosixPath", "PureWindowsPath"})


def _document_like(obj: Any) -> bool:
    """LangChain Document (and lookalikes) carry text on ``page_content``."""
    return isinstance(getattr(obj, "page_content", None), str)


def _fspath_str(raw: Any) -> str:
    if hasattr(raw, "__fspath__"):
        try:
            raw = os.fspath(raw)
        except Exception:
            return ""
    return raw if isinstance(raw, str) else ""


def _looks_like_upload(obj: Any) -> bool:
    """True for Chainlit AskFileResponse-style handles: on-disk ``path`` + filename ``name``.

    Must not treat pathlib.Path, open files, or a dict that merely has a ``path``
    key (config, kwargs) as an upload — that would read arbitrary files and
    rewrite customer objects.
    """
    if obj is None or isinstance(obj, (str, bytes, bytearray, list, tuple, int, float, bool)):
        return False
    if type(obj).__name__ in _PATH_TYPE_NAMES:
        return False
    if isinstance(obj, dict):
        path, name = obj.get("path"), obj.get("name")
        extra = "size" in obj or "type" in obj or isinstance(obj.get("text"), str)
    else:
        path, name = getattr(obj, "path", None), getattr(obj, "name", None)
        extra = getattr(obj, "size", None) is not None or bool(getattr(obj, "type", None))
    path = _fspath_str(path)
    if path and os.path.isfile(path):
        return extra or (isinstance(name, str) and bool(name))
    # Fall through to the in-memory/stream shape (Werkzeug FileStorage and
    # similar): these frameworks never write the upload to disk unless the
    # app explicitly calls .save(), so an on-disk path never exists here —
    # not a case this function's disk-path branch above can ever cover.
    return _looks_like_stream_upload(obj)


def _looks_like_stream_upload(obj: Any) -> bool:
    """True for stream-based upload handles (Werkzeug ``FileStorage`` and
    similar): a readable/seekable stream plus a filename, but — unlike the
    Chainlit-style handles above — content lives in memory or a spooled temp
    file, never an on-disk path, until the framework explicitly saves it."""
    if obj is None or isinstance(obj, (str, bytes, bytearray, list, tuple, int, float, bool, dict)):
        return False
    if type(obj).__name__ in _PATH_TYPE_NAMES:
        return False
    target = _stream_upload_target(obj)
    filename = getattr(obj, "filename", None) or getattr(obj, "name", None)
    return (
        callable(getattr(target, "read", None))
        and callable(getattr(target, "seek", None))
        and isinstance(filename, str)
        and bool(filename)
    )


def _stream_upload_target(obj: Any) -> Any:
    """The actual readable/seekable stream for a stream-upload handle —
    ``obj.stream`` for Werkzeug's FileStorage, else ``obj`` itself for a bare
    file-like object."""
    stream = getattr(obj, "stream", None)
    return stream if stream is not None else obj


def _read_stream_upload_text(obj: Any, limit: int = _MAX_INLINE_FILE_BYTES) -> "str | None":
    """UTF-8 text from a stream-upload handle, restoring the stream's read
    position afterward. This same object is normally used for the real
    upload call immediately after the guardrail check — leaving it consumed
    or mispositioned would silently empty out that upload."""
    target = _stream_upload_target(obj)
    try:
        pos = target.tell()
    except Exception:
        pos = 0
    try:
        target.seek(0)
        raw = target.read(limit)
    except Exception:
        return None
    finally:
        try:
            target.seek(pos)
        except Exception:
            pass
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if b"\x00" in raw[:2048]:
        return None
    return raw.decode("utf-8", errors="replace")


def _write_stream_upload_text(obj: Any, text: str) -> bool:
    """Overwrite a stream-upload handle's content with masked text, leaving
    the stream positioned at 0 so the real upload call right after reads the
    redacted version instead of the original."""
    target = _stream_upload_target(obj)
    try:
        target.seek(0)
        if hasattr(target, "truncate"):
            target.truncate()
        target.write(text.encode("utf-8"))
        target.seek(0)
        return True
    except Exception as exc:
        _logger.warning("gr_stub_client: could not write masked content back to upload stream (%s)", exc)
        return False


def _file_like_path(obj: Any) -> str:
    """On-disk path for an upload handle, else ``\"\"`` (including for a
    stream-based upload handle, which has no on-disk path by definition —
    see ``_looks_like_stream_upload``)."""
    if not _looks_like_upload(obj):
        return ""
    if isinstance(obj, dict):
        return _fspath_str(obj.get("path"))
    path = _fspath_str(getattr(obj, "path", None))
    return path if path and os.path.isfile(path) else ""


def _read_text_file(path: str, limit: int = _MAX_INLINE_FILE_BYTES) -> "str | None":
    """UTF-8 text, or None when the file is binary / unreadable (do not rewrite it)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return None
    if b"\x00" in raw[:2048]:
        return None
    return raw.decode("utf-8", errors="replace")


def _write_text_file(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _payload_is_uploaded_files(payload: Any) -> bool:
    items = payload if isinstance(payload, (list, tuple)) else [payload]
    return any(_looks_like_upload(item) for item in items[:_MAX_INLINE_FILES])


def _is_pydantic_model(obj: Any) -> bool:
    return bool(
        getattr(obj, "model_fields", None)
        or getattr(obj, "__fields__", None)
        or getattr(obj, "__pydantic_fields__", None)
    )


def _pydantic_dump(obj: Any) -> "dict | None":
    """Dump only real Pydantic models — never a random ``.dict()`` method."""
    if not _is_pydantic_model(obj):
        return None
    dump = getattr(obj, "model_dump", None) or getattr(obj, "dict", None)
    if not callable(dump):
        return None
    try:
        data = dump()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _jsonable_payload(payload: Any, _depth: int = 0, _seen: "set[int] | None" = None) -> Any:
    """JSON-serializable form of payload (unwrap Request / Document / upload handles)."""
    if payload is None or isinstance(payload, (str, int, float, bool)):
        return payload
    if _depth > _MAX_JSONABLE_DEPTH:
        return None
    if _seen is None:
        _seen = set()
    oid = id(payload)
    if oid in _seen:
        return None
    if isinstance(payload, dict):
        _seen.add(oid)
        path = _file_like_path(payload)
        if path and not isinstance(payload.get("text"), str):
            text = _read_text_file(path)
            if text is not None:
                payload = {**payload, "text": text}
        return {str(k): _jsonable_payload(v, _depth + 1, _seen) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        _seen.add(oid)
        items = payload[:_MAX_INLINE_FILES] if _payload_is_uploaded_files(payload) else payload
        return [_jsonable_payload(item, _depth + 1, _seen) for item in items]
    if isinstance(payload, (bytes, bytearray)):
        return _decode_body(payload)
    data = getattr(payload, "data", None)
    if isinstance(payload, urllib.request.Request) or (
        type(payload).__name__ == "Request" and data is not None
    ):
        return _decode_body(data)
    if _document_like(payload):
        meta = getattr(payload, "metadata", None)
        out: dict[str, Any] = {"page_content": payload.page_content}
        if isinstance(meta, dict):
            out["metadata"] = _jsonable_payload(meta, _depth + 1, _seen)
        return out
    path = _file_like_path(payload)
    if path:
        text = _read_text_file(path)
        return {
            "name": str(getattr(payload, "name", "") or os.path.basename(path)),
            "path": path,
            "text": text if text is not None else "",
        }
    if _looks_like_stream_upload(payload):
        text = _read_stream_upload_text(payload)
        return {
            "name": str(getattr(payload, "filename", "") or getattr(payload, "name", "") or ""),
            "path": "",
            "text": text if text is not None else "",
        }
    dumped = _pydantic_dump(payload)
    if dumped is not None:
        _seen.add(oid)
        return _jsonable_payload(dumped, _depth + 1, _seen)
    return payload


def _json_default(obj: Any) -> Any:
    """json.dumps default: coerce leftover objects instead of failing open."""
    try:
        coerced = _jsonable_payload(obj)
    except Exception:
        return str(obj)
    if coerced is not obj:
        return coerced
    return str(obj)


def _wire_payload(payload: Any) -> Any:
    """JSON body for /enforce. File handles become ``{text, files}`` so PII routines see contents."""
    data = _jsonable_payload(payload)
    if not _payload_is_uploaded_files(payload):
        return data
    if isinstance(data, list):
        texts = [item.get("text") or "" for item in data if isinstance(item, dict)]
        return {"text": "\n".join(texts), "files": data}
    if isinstance(data, dict) and "text" in data:
        return data
    return {"text": data}


def _looks_like_object_repr(text: str) -> bool:
    """True for ``str(Document)`` / ``str(obj)`` dumps, not real masked text."""
    if text.startswith("page_content=") or "page_content=" in text[:80]:
        return True
    if text.startswith("<") and "object at 0x" in text:
        return True
    return False


def _masked_text_from(masked: Any) -> "str | None":
    """Extract the masked text a routine returned, from either shape a
    decision's payload can take: the ``{"text": ..., "path": ...}``/
    ``{"page_content": ...}`` dict this SDK builds for file-like uploads, or
    a bare masked string."""
    if isinstance(masked, dict):
        raw = masked.get("text")
        if raw is None:
            raw = masked.get("page_content")
        return raw if isinstance(raw, str) else None
    if isinstance(masked, str) and not _looks_like_object_repr(masked):
        return masked
    return None


def _rehydrate_item(original: Any, masked: Any) -> Any:
    """Write masked fields onto the original object when possible."""
    if original is None:
        return masked
    if isinstance(original, urllib.request.Request):
        return _reapply_payload(original, masked)
    if _document_like(original):
        if isinstance(masked, dict) and "page_content" in masked:
            original.page_content = masked["page_content"]
            if isinstance(masked.get("metadata"), dict) and hasattr(original, "metadata"):
                original.metadata = masked["metadata"]
            return original
        if isinstance(masked, str) and not _looks_like_object_repr(masked):
            original.page_content = masked
            return original
        return original
    path = _file_like_path(original)
    if path:
        text = _masked_text_from(masked)
        if text is not None and _read_text_file(path) is not None:
            try:
                _write_text_file(path, text)
            except OSError as exc:
                _logger.warning("gr_stub_client: could not write masked file %s (%s)", path, exc)
        return original
    if _looks_like_stream_upload(original):
        text = _masked_text_from(masked)
        if text is not None:
            _write_stream_upload_text(original, text)
        return original
    if isinstance(original, str):
        if isinstance(masked, str) and not _looks_like_object_repr(masked):
            return masked
        if isinstance(masked, dict):
            raw = masked.get("text")
            if raw is None:
                raw = masked.get("page_content")
            if isinstance(raw, str):
                return raw
        return original
    if type(masked) is type(original):
        return masked
    if not isinstance(original, (str, int, float, bool, dict, list, type(None))):
        return original
    return masked


def _reapply_payload(original: Any, masked: Any) -> Any:
    """Put masked data back on the live object; keep the original type."""
    if isinstance(original, urllib.request.Request):
        if isinstance(masked, (dict, list)):
            original.data = json.dumps(masked).encode("utf-8")
        elif isinstance(masked, str):
            original.data = masked.encode("utf-8")
        elif isinstance(masked, (bytes, bytearray)):
            original.data = bytes(masked)
        return original
    if isinstance(original, (list, tuple)) and isinstance(masked, list):
        rehydrated = [
            _rehydrate_item(item, masked[i] if i < len(masked) else item)
            for i, item in enumerate(original)
        ]
        return type(original)(rehydrated) if isinstance(original, tuple) else rehydrated
    if isinstance(original, (list, tuple)) and isinstance(masked, dict):
        files = masked.get("files")
        if isinstance(files, list):
            by_path = {
                str(entry.get("path") or ""): entry
                for entry in files
                if isinstance(entry, dict)
            }
            for item in original:
                path = _file_like_path(item)
                entry = by_path.get(path)
                if entry is not None:
                    _rehydrate_item(item, entry)
            return original
        if "text" in masked and original:
            _rehydrate_item(original[0], masked)
            return original
    return _rehydrate_item(original, masked)


def persist_runtime_mask_to_source(
    masked_payload: Any,
    *,
    source_file: str,
    variable_name: str,
    before_line: int | None = None,
) -> bool:
    """Replace a source literal assignment with the masked value. Scalars only."""
    if not isinstance(masked_payload, (str, int, float, bool)):
        return False
    masked_text = str(masked_payload)
    path = os.path.abspath(source_file)
    if not os.path.isfile(path):
        _logger.warning("persist_runtime_mask_to_source: missing file %s", path)
        return False
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        _logger.warning("persist_runtime_mask_to_source: read failed %s (%s)", path, exc)
        return False

    assign_line = _find_assignment_line(lines, variable_name, before_line or len(lines))
    if assign_line is None:
        _logger.debug(
            "persist_runtime_mask_to_source: no assignment for %r before line %s in %s",
            variable_name, before_line, path,
        )
        return False
    span = _assignment_stmt_span(lines, assign_line)
    if span is None:
        _logger.warning(
            "persist_runtime_mask_to_source: could not span assignment for %r at line %d in %s",
            variable_name, assign_line, path,
        )
        return False
    start, end = span
    original = "".join(lines[start : end + 1])
    if "_gr_client" in original or "SiteDescriptor" in original:
        _logger.debug(
            "persist_runtime_mask_to_source: skip guardrail stub assignment %r in %s",
            variable_name, path,
        )
        return False
    if re.search(r"""=\s*(?:\()?\s*f(?:'''|\"\"\"|'|\")""", original) or re.search(
        r"\bf(?:'''|\"\"\"|'|\")", original
    ):
        _logger.info(
            "persist_runtime_mask_to_source: skip f-string assignment %r in %s",
            variable_name, path,
        )
        return False
    indent_match = re.match(r"^(\s*)", lines[start])
    base_indent = indent_match.group(1) if indent_match else ""
    quote = "'''" if '"""' in masked_text else '"""'
    new_lines = [f"{base_indent}{variable_name} = {quote}{masked_text}{quote}\n"]
    rewritten = lines[:]
    rewritten[start : end + 1] = new_lines
    try:
        compile("".join(rewritten), path, "exec")
    except SyntaxError as exc:
        _logger.warning(
            "persist_runtime_mask_to_source: rewrite would be invalid Python (%s) — left %s unchanged",
            exc, path,
        )
        return False
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(rewritten)
    except OSError as exc:
        _logger.warning("persist_runtime_mask_to_source: write failed %s (%s)", path, exc)
        return False
    _logger.info(
        "persist_runtime_mask_to_source: updated %s lines %d-%d (%r)",
        path, start + 1, end + 1, variable_name,
    )
    return True


def _normalize_http_error_detail(raw: Any) -> dict[str, Any]:
    """FastAPI wraps as ``{detail: {...}}``; some gateways send the dict unwrapped."""
    if not isinstance(raw, dict):
        return {}
    detail = raw.get("detail", raw)
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        return detail[0]
    return {}


def _read_http_error_detail(exc: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        body = exc.read()
    except Exception:
        return {}
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except Exception:
        return {}
    return _normalize_http_error_detail(parsed)


def _is_unknown_site_error(detail: dict[str, Any]) -> bool:
    err = str(detail.get("error") or "").strip()
    return err in ("unknown_site", "unknown_site_id", "candidate_policies_mismatch")


def _should_register_unknown_site(detail: dict[str, Any], site_id: str) -> bool:
    """Register leftover / unregistered sites. Never treat a policy block as unknown."""
    if not (site_id or "").strip():
        return False
    if _is_unknown_site_error(detail):
        return True
    if detail.get("blocked_by") or str(detail.get("error") or "") == "request_blocked":
        return False
    return not detail


def _candidate_policies_from_mappings(mappings: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for mapping in mappings:
        if not isinstance(mapping, dict) or not mapping.get("policy_id"):
            continue
        out.append({
            "policy_id": mapping["policy_id"],
            "guardrail_id": mapping.get("guardrail_id"),
            "policy_version": mapping.get("policy_version"),
        })
    return out


def _apply_registered_mappings(
    body: dict[str, Any], site: "SiteDescriptor", mappings: list[Any],
) -> None:
    if not mappings:
        return
    candidates = _candidate_policies_from_mappings(mappings)
    body["candidate_policies"] = candidates
    try:
        site.candidate_policies = candidates
    except Exception:
        pass


def _finalize_decision(decision: Decision, original: Any) -> Decision:
    """Never return leftover PII on allow/mask. Policy blocks stay blocked."""
    masked, n = _mask_pii_tree(decision.payload)
    if not n:
        return decision
    decision.payload = masked
    if decision.status != "block":
        decision.status = "mask"
        decision.actions_applied = list(decision.actions_applied or []) + [
            {"policy_id": "AI_DAT_SEC_012", "action": "mask", "count": n},
        ]
        extra = f"local PII mask ({n} hit(s))"
        decision.warning = f"{decision.warning} — {extra}" if decision.warning else extra
    return decision


def _announce_enforce(url: str, hop: str, status: str, extra: str = "") -> None:
    """Always visible on stderr so a local customer run shows /enforce actually fired."""
    suffix = f" {extra}" if extra else ""
    msg = f"[lineaje.enforce] POST {url}/enforce {hop} → {status}{suffix}"
    _logger.info("%s", msg)
    try:
        print(msg, file=sys.stderr, flush=True)
    except Exception:
        pass


def _post_json(
    url: str, path: str, body: dict[str, Any], pat: str, timeout: float,
) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(body, default=_json_default).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {pat}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _post_enforce(url: str, body: dict[str, Any], pat: str, timeout: float) -> dict[str, Any]:
    return _post_json(url, "/enforce", body, pat, timeout)


def _ensure_site_registered(
    url: str,
    site: "SiteDescriptor",
    tenant_id: str,
    pat: str,
    timeout: float,
) -> "list[Any] | None":
    """POST /admin/site-manifest/register once per site_id, then /enforce can resolve it.

    Returns compiled ``policy_mappings`` (possibly empty) on success, or
    ``None`` if registration failed. Scan-time registration often lands in a
    different SQLite than commercialdev; runtime check() self-registers on
    unknown_site so leftover stubs still enforce with site_id.
    """
    site_id = (getattr(site, "site_id", "") or "").strip()
    if not site_id:
        return None
    if site_id in _SITE_REGISTERED:
        return _SITE_POLICY_MAPPINGS.get(site_id, [])
    if site_id in _SITE_REGISTER_ATTEMPTED:
        return None
    _SITE_REGISTER_ATTEMPTED.add(site_id)
    if not tenant_id:
        _logger.warning(
            "gr_stub_client: cannot register site_id=%s — no tenant_id in token/body",
            site_id,
        )
        return None
    try:
        result = _post_json(
            url,
            "/admin/site-manifest/register",
            {
                "tenant_id": tenant_id,
                "site_id": site_id,
                "phase": getattr(site, "phase", "") or "",
                "boundary": getattr(site, "boundary", None) or {},
                "components": getattr(site, "components", None) or {},
            },
            pat,
            timeout,
        )
    except Exception as exc:
        _logger.warning(
            "gr_stub_client: site-manifest register failed for %s (%s) — "
            "will retry /enforce without site_id",
            site_id, exc,
        )
        return None
    if not result.get("ok"):
        _logger.warning(
            "gr_stub_client: site-manifest register rejected for %s (%s) — "
            "will retry /enforce without site_id",
            site_id, result.get("error"),
        )
        return None
    mappings = result.get("policy_mappings") or []
    _SITE_REGISTERED.add(site_id)
    _SITE_POLICY_MAPPINGS[site_id] = mappings
    _logger.info(
        "gr_stub_client: registered site_id=%s tenant=%s mappings=%d on %s",
        site_id, tenant_id, len(mappings), url,
    )
    return mappings


def _decision_for_genuine_block(
    site: "SiteDescriptor", url: str, hop: str, detail: dict, payload: Any,
) -> "Decision":
    """A confirmed policy block (``detail["blocked_by"]`` populated, not an
    unknown_site resolution issue) — respects ``site.fail_mode`` exactly like
    the first-attempt 403 handler in ``check()`` does. Factored out so the
    unknown_site retry paths below can reach the SAME real-block handling
    when a retry's own 403 turns out to be a genuine block rather than
    another unknown_site cycle — see those callers' comments for the bug
    this fixes (a real block during a retry used to fall through to
    ``_fail_response``'s generic "unresolved unknown_site" path, which
    fails OPEN even when fail_mode=BLOCK, since that path's own safety
    check explicitly excludes anything with "unknown_site" in its warning
    text — exactly the string used to describe that fallback).
    """
    blocked_by = detail.get("blocked_by") or []
    policy_id = blocked_by[0].get("policy_id", "unknown") if blocked_by else "unknown"
    reason = detail.get("message", "Request denied by policy enforcement.")
    if getattr(site, "fail_mode", None) != "BLOCK":
        _announce_enforce(
            url, hop, "allow",
            extra=f"HTTP 403 {policy_id} passed through (fail_mode={getattr(site, 'fail_mode', '') or 'ALLOW_WITH_AUDIT'})",
        )
        allowed = Decision({
            "status": "allow",
            "result": {"data": payload},
            "actions_applied": [{"policy_id": policy_id, "action": "block"}],
            "recommendations": [],
            "warning": reason,
        }, site_id=site.site_id)
        return _finalize_decision(allowed, payload)
    _announce_enforce(url, hop, "block", extra=f"policy={policy_id} {reason}")
    blocked = Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{"policy_id": policy_id, "action": "block"}],
        "recommendations": [],
        "warning": reason,
    }, site_id=site.site_id)
    _maybe_record_process_block(blocked, site)
    return _finalize_decision(blocked, payload)


def _genuine_block_detail_from_retry_exc(retry_exc: Exception, site_id: str) -> "dict | None":
    """None unless ``retry_exc`` is an HTTPError(403) carrying a real policy
    block — i.e. NOT another unknown_site cycle (that gets a fresh register/
    retry of its own upstream, not folded into this check). Callers use
    this to route a retry's own confirmed block through
    ``_decision_for_genuine_block`` instead of the generic
    "unresolved unknown_site" fail-open/closed fallback.
    """
    if not isinstance(retry_exc, urllib.error.HTTPError) or retry_exc.code != 403:
        return None
    detail = _read_http_error_detail(retry_exc)
    if _should_register_unknown_site(detail, site_id):
        return None
    if not detail.get("blocked_by"):
        return None
    return detail


def check(
    site: SiteDescriptor,
    payload: Any,
    content_type: str = "application/json",
    *,
    tenant_id: str = "",
    correlation_id: "str | None" = None,
    event_id: "str | None" = None,
    operation_identity: "dict | None" = None,
    gr_service_url: "str | None" = None,
    lineaje_pat: str = "",
    timeout: "float | None" = None,
) -> Decision:
    """POST /enforce for this site. Never raises; 403 → ``decision.blocked``.

    After a fail-closed policy block, later calls for *other* site_ids skip
    the POST entirely (do not extract/upload file contents for PII/MCP
    sites). The blocking site may still re-POST.
    """
    prior = _process_block_for_other_site(getattr(site, "site_id", "") or "")
    if prior is not None:
        return _skipped_other_site_decision(site, payload, prior)
    local_block = _local_quarantined_skill_decision(site, payload)
    if local_block is not None:
        return local_block
    if timeout is None:
        timeout = _resolve_enforce_timeout_seconds()
    url = _resolve_gr_origin(gr_service_url)
    if not url:
        return Decision(
            _fail_response(site, "GR_SERVICE_URL not configured — guardrail skipped", payload),
            site_id=site.site_id,
        )

    pat = _resolve_enforce_bearer(lineaje_pat)

    try:
        wire_data = _wire_payload(payload)
    except Exception as exc:
        _logger.warning("gr_stub_client.check: payload serialize failed (%s) — original object unchanged", exc)
        wire_data = {"text": None}

    wire_src, wire_dst = _source_dest_from_site(site)
    if _payload_is_uploaded_files(payload):
        # AskFileMessage / upload handles were classified as api→agent
        # (post_tool + external_endpoint). The file body lives on disk; PII
        # upload policies are bound to file_upload (file_storage→agent).
        wire_src, wire_dst = "file_storage", "agent"
    body: dict[str, Any] = {
        "contract_version": "2.0",
        "event_id": event_id or _new_ulid(),
        "correlation_id": correlation_id or _new_ulid(),
        "tenant_id": tenant_id or os.environ.get("GR_TENANT_ID", ""),
        "site_id": site.site_id,
        "site_manifest_version": site.site_manifest_version,
        "phase": site.phase,
        "candidate_policies": site.candidate_policies,
        "boundary": site.boundary,
        "components": site.components,
        "source_type": wire_src,
        "destination_type": wire_dst,
        "payload": {"mode": "inline", "content_type": content_type, "data": wire_data},
        "client_deadline_hint_ms": int(timeout * 1000),
        "resume_token": None,
        "redecision_token": None,
        "operation_identity": operation_identity,
    }

    hop = f"site_id={site.site_id}" if site.site_id else "site_id=<unknown>"

    def _decision_from(result: dict[str, Any]) -> Decision:
        server_result = result.get("result")
        wrapped = dict(result)
        if not isinstance(wire_data, dict) and isinstance(server_result, dict) and "text" in server_result:
            wrapped["result"] = {"data": server_result["text"]}
        else:
            wrapped["result"] = {"data": server_result}
        decision = Decision(wrapped, site_id=site.site_id)
        try:
            decision.payload = _reapply_payload(payload, decision.payload)
        except Exception as exc:
            _logger.warning("gr_stub_client.check[%s]: reapply failed (%s) — original payload kept", hop, exc)
            decision.payload = payload
        finished = _finalize_decision(decision, payload)
        _maybe_record_process_block(finished, site)
        return finished

    try:
        result = _post_enforce(url, body, pat, timeout)
        if result.get("status") == "escalate":
            _logger.warning("gr_stub_client.check[%s]: escalation flagged — passing through for human review", hop)
        decision = _decision_from(result)
        _announce_enforce(
            url, hop, decision.status,
            extra=f"actions={decision.actions_applied or []}",
        )
        return decision
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            detail = _read_http_error_detail(exc)
            if _should_register_unknown_site(detail, str(body.get("site_id") or "")):
                register_tenant = _tenant_id_from_bearer(pat, str(body.get("tenant_id") or ""))
                mappings = _ensure_site_registered(url, site, register_tenant, pat, timeout)
                if mappings is not None:
                    _apply_registered_mappings(body, site, mappings)
                    _announce_enforce(
                        url, hop, "unknown_site",
                        extra="registered site manifest — retrying with site_id",
                    )
                    try:
                        result = _post_enforce(url, body, pat, timeout)
                        decision = _decision_from(result)
                        _announce_enforce(
                            url, hop, decision.status,
                            extra=f"actions={decision.actions_applied or []}",
                        )
                        return decision
                    except Exception as retry_exc:
                        # A CONFIRMED block on this retry (not another unknown_site
                        # cycle) must go through the same fail_mode-respecting path
                        # as the very first attempt — see
                        # _genuine_block_detail_from_retry_exc's docstring for the
                        # bug this closes: falling through to the generic
                        # "unresolved unknown_site" _fail_response below silently
                        # turned a real block into an allow whenever site
                        # registration was flaky, regardless of fail_mode=BLOCK.
                        retry_detail = _genuine_block_detail_from_retry_exc(
                            retry_exc, str(body.get("site_id") or ""),
                        )
                        if retry_detail is not None:
                            return _decision_for_genuine_block(site, url, hop, retry_detail, payload)
                        _logger.warning(
                            "gr_stub_client.check[%s]: retry after register failed (%s)",
                            hop, retry_exc,
                        )
                _announce_enforce(
                    url, hop, "unknown_site",
                    extra="retrying without site_id so policies still evaluate",
                )
                retry_body = dict(body)
                retry_body["site_id"] = ""
                try:
                    result = _post_enforce(url, retry_body, pat, timeout)
                    decision = _decision_from(result)
                    _announce_enforce(
                        url, hop, decision.status,
                        extra=f"(no site_id) actions={decision.actions_applied or []}",
                    )
                    return decision
                except Exception as retry_exc:
                    # Same reasoning as the "retry after register" branch above —
                    # a genuine block on the no-site_id retry (the common case,
                    # since evaluating the full tenant policy set with no site
                    # scoping is exactly what turns up a real AI_APP_SEC_006/028
                    # etc. match) must not be folded into the generic
                    # unknown_site-unresolved fallback below.
                    retry_detail = _genuine_block_detail_from_retry_exc(retry_exc, "")
                    if retry_detail is not None:
                        return _decision_for_genuine_block(site, url, hop, retry_detail, payload)
                    _logger.warning("gr_stub_client.check[%s]: retry without site_id failed (%s)", hop, retry_exc)
                masked_unknown = _fail_response(
                    site, "unknown_site unresolved after register/retry", payload,
                )
                _announce_enforce(url, hop, masked_unknown["status"], extra=masked_unknown.get("warning") or "")
                return Decision(masked_unknown, site_id=site.site_id)
            return _decision_for_genuine_block(site, url, hop, detail, payload)
        _logger.warning(
            "gr_stub_client.check[%s]: GR service call failed (%s) POST %s/enforce — %s",
            hop, exc, url,
            "failing closed (fail_mode=BLOCK)" if site.fail_mode == "BLOCK" else "failing open",
        )
        return Decision(_fail_response(site, f"GR service error: {exc}", payload), site_id=site.site_id)
    except Exception as exc:
        _logger.warning(
            "gr_stub_client.check[%s]: GR service call failed (%s) POST %s/enforce — %s",
            hop, exc, url,
            "failing closed (fail_mode=BLOCK)" if site.fail_mode == "BLOCK" else "failing open",
        )
        return Decision(_fail_response(site, f"GR service unreachable: {exc}", payload), site_id=site.site_id)


def enforce(
    site: SiteDescriptor,
    payload: Any,
    content_type: str = "application/json",
    *,
    variable_name: str = "",
    source_file: str = "",
    before_line: "int | None" = None,
) -> Any:
    """Single call-site entry point for an inserted stub — call this, get the value back.

    ``check()`` never raises (infra failures fail open/closed internally via
    ``_fail_response``), so the only exception surface here is truly
    unexpected breakage in the call itself (e.g. a bad companion version).
    This wraps that surface, the blocked -> ``PermissionError`` raise, and
    the optional persist-to-source rewrite, so an inserted stub only needs a
    single call plus a narrow ``except GuardrailUnavailableError`` around it,
    instead of inlining its own try/except/logging block.

    A block caused by the GR service itself being unreachable/misconfigured
    (as opposed to a live decision that actually found a violation) raises
    ``GuardrailUnavailableError`` (a ``PermissionError`` subclass) instead of
    a bare ``PermissionError`` — so a generated call site can catch that
    narrower type to fail OPEN on an outage without weakening the
    fail-closed guarantee for a genuine policy block.

    Leftover log_emit / user_interface stubs sit on FastAPI handlers (error
    log lines, GET /chat/jobs polls). Raising there 500s the customer app
    even after the LLM hop already blocked. Those sites return a safe
    payload instead of raising; LLM / tool / MCP / file hops still raise.
    """
    try:
        decision = check(site, payload, content_type=content_type)
    except PermissionError:
        raise
    except Exception as exc:
        _logger.warning(
            "Lineaje guardrail unavailable at site_id=%r (%s) — %s",
            site.site_id, exc,
            "blocking (fail_mode=BLOCK)" if site.fail_mode == "BLOCK" else "passing data through unchecked",
        )
        if site.fail_mode == "BLOCK":
            raise GuardrailUnavailableError(
                f"Lineaje guardrail unavailable at site_id={site.site_id!r} and fail_mode=BLOCK: {exc}"
            ) from exc
        return payload
    if decision.blocked:
        if _stub_must_not_crash_host(site):
            _logger.warning(
                "gr_stub_client.enforce[site_id=%s]: policy block — not raising "
                "(leftover log/UI stub must not crash the host): %s",
                site.site_id, decision.warning,
            )
            return _payload_after_host_safe_block(site, decision, payload)
        raise decision.as_error()
    if variable_name and source_file:
        persist_runtime_mask_to_source(
            decision.payload, source_file=source_file, variable_name=variable_name, before_line=before_line,
        )
    return decision.payload
