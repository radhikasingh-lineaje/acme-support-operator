"""Constants for the Acme Support Ticket Operator.

Policy IDs below map to the UnifAI policies tested in Confluence:
"UnifAI Stubs and Guardrails - Sept 2026" -> Test Cases - 22nd Sept 2026.
"""

from pathlib import Path


def _ai_app_sec_006_normalize_model_name(model_name: str) -> str:
    return "".join(ch for ch in str(model_name).lower() if ch.isalnum())


_ai_app_sec_006_disapproved_models = {
    _ai_app_sec_006_normalize_model_name(name)
    for name in (
        "DeepSeek chat",
        "DeepSeek r1",
        "DeepSeek r1-distill-llama-70b",
        "DeepSeek reasoner",
        "custom_llm_client null",
        "deepseek-chat null",
        "openrouter null",
        "us.deepseek.r1-v1:0 null",
        "LLaMA",
        "llama-4-scout",
        "meta-llama/llama-4-scout",
    )
}


def _ai_app_sec_006_validate_model_name(model_name: str) -> str:
    normalized = _ai_app_sec_006_normalize_model_name(model_name)
    for blocked in _ai_app_sec_006_disapproved_models:
        if blocked and blocked in normalized:
            raise ValueError(f"Disapproved model configured: {model_name}")
    return model_name

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
    "triage": _ai_app_sec_006_validate_model_name("openai/gpt-4o-mini"),
    "resolver": _ai_app_sec_006_validate_model_name("openai/gpt-4o-mini"),
}

# --- Ticket handling --------------------------------------------------------
TICKET_CATEGORIES = ["billing", "account", "technical", "other"]
TICKET_PRIORITIES = ["low", "medium", "high"]

SAMPLE_TICKET = (
    "Hi, I'm Jane Doe from Portland, Oregon (SSN 123-45-6789, "
    "jane.doe@example.com, 503-555-0199). I was charged twice for my "
    "subscription this month on card 4111 1111 1111 1111. Please help me get a refund."
)

# --- Paths ------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT_DIR / "logs"
LLM_IO_LOG_FILE = LOG_DIR / "llm_io.jsonl"
