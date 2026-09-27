"""OpenRouter model access for the support agents (via langchain-openai)."""

import json
import logging
import os
import re
from datetime import datetime, timezone

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI

from config.constants import DEFAULT_MODELS, LLM_IO_LOG_FILE, OPENROUTER_BASE_URL

logger = logging.getLogger(__name__)


_ai_app_sec_006_DISALLOWED_MODELS = {
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "openrouternull",
    "usdeepseekr1v10null",
}


def _ai_app_sec_006_normalize_model_name(model_name: str) -> str:
    return re.sub(r"[\s\-_.:]", "", (model_name or "").casefold())


def _ai_app_sec_006_validate_model_name(model_name: str) -> str:
    _ai_app_sec_006_normalized = _ai_app_sec_006_normalize_model_name(model_name)
    if _ai_app_sec_006_normalized in _ai_app_sec_006_DISALLOWED_MODELS:
        raise ValueError(f"Configured model '{model_name}' is disallowed by organization policy")
    return model_name


def resolve_model_name(agent: str, override: str | None = None) -> str:
    """Model for an agent: UI override, then env (<AGENT>_MODEL), then default."""
    return (
        (override or "").strip()
        or os.getenv(f"{agent.upper()}_MODEL", "").strip()
        or DEFAULT_MODELS[agent]
    )


def get_model(agent: str, override: str | None = None) -> ChatOpenAI:
    model_name = resolve_model_name(agent, override)
    model_name = _ai_app_sec_006_validate_model_name(model_name)

    # [AI_APP_SEC_006] Use only LLMs from the organization's approved list — UNGUARDED:
    # [AI_APP_SEC_028] Do not use LLMs from the organization's disallowed list — UNGUARDED:
    # any model name from env or the UI sidebar is used as-is, with no allow/deny check.
    logger.info("llm_call agent=%s model=%s", agent, model_name)
    return ChatOpenAI(
        model=model_name,
        base_url=OPENROUTER_BASE_URL,
        api_key=os.getenv("OPENROUTER_API_KEY"),
        temperature=0.2,
        max_tokens=400,
    )


def invoke(agent: str, messages: list[BaseMessage], override: str | None = None) -> tuple[str, str]:
    """Call the agent's model; returns (response_text, model_name)."""
    model = get_model(agent, override)
    response = model.invoke(messages)
    _log_io(agent, model.model_name, messages, response.content)
    return response.content, model.model_name


def _log_io(agent: str, model_name: str, messages: list[BaseMessage], output: str) -> None:
    # TEST AID for [AI_DAT_SEC_011]: when LLM_IO_LOG=true, record exactly what was sent
    # to / received from OpenRouter, so testers can verify whether PII reached the model.
    # This file contains PII by design — do not enable outside testing.
    if os.getenv("LLM_IO_LOG", "").lower() != "true":
        return
    LLM_IO_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "model": model_name,
        "input": [{"role": m.type, "content": m.content} for m in messages],
        "output": output,
    }
    with LLM_IO_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
