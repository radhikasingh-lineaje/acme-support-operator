"""Constants for the Acme Support Ticket Operator.

Policy IDs below map to the UnifAI policies tested in Confluence:
"UnifAI Stubs and Guardrails - Sept 2026" -> Test Cases - 22nd Sept 2026.
"""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m


from pathlib import Path

# --- UnifAI policy IDs (referenced in code comments as [POLICY_ID]) ---------
POLICY_APPROVED_LLMS = "AI_APP_SEC_006"     # Use only LLMs from the organization's approved list
POLICY_DISALLOWED_LLMS = "AI_APP_SEC_028"   # Do not use LLMs from the organization's disallowed list
POLICY_NO_PII_IN_LOGS = "AI_DAT_SEC_010"    # Do not log PII
POLICY_NO_PII_TO_MODELS = "AI_DAT_SEC_011"  # Do not send PII to AI Models
POLICY_MASK_PII_ON_UI = "AI_DAT_SEC_012"    # Mask PII on user interfaces

# --- OpenRouter / models ----------------------------------------------------
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Default model per agent; overridable via env (TRIAGE_MODEL / RESOLVER_MODEL)
# and via the Streamlit sidebar.
DEFAULT_MODELS = {
    "triage": "meta-llama/llama-4-scout",
    "resolver": "meta-llama/llama-4-scout",
}

# --- Ticket handling --------------------------------------------------------
TICKET_CATEGORIES = ["billing", "account", "technical", "other"]
TICKET_PRIORITIES = ["low", "medium", "high"]

SAMPLE_TICKET = (
    "Hi, I'm Jane Doe from Portland, Oregon (SSN 123-45-6789, "
    "jane.doe@example.com, 503-555-0199). I was charged twice for my "
    "subscription this month on card 4111 1111 1111 1111. Please help me get a refund."
)
# LINEAJE: enforce() `SAMPLE_TICKET` at agent->system security_decision — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_025 (No file should contain any PII.). Mask/block; do not remove without review. site_id='site:sha256:5a1a0abf4fb416890efb51629697d3f5d7c32854fc41ba404040f49faf787f1a'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5a1a0abf4fb416890efb51629697d3f5d7c32854fc41ba404040f49faf787f1a', phase='security_decision', boundary={'source': 'agent_message', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='system')
try:
    SAMPLE_TICKET = _gr_client.enforce(_gr_site, SAMPLE_TICKET, content_type='application/json', variable_name='SAMPLE_TICKET', source_file=__file__, before_line=30)
except _gr_client.GuardrailUnavailableError:
    pass

# --- Paths ------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT_DIR / "logs"
LLM_IO_LOG_FILE = LOG_DIR / "llm_io.jsonl"
