"""OpenRouter model access for the support agents (via langchain-openai)."""
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


import json
import logging
import os
from datetime import datetime, timezone

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI

from config.constants import DEFAULT_MODELS, LLM_IO_LOG_FILE, OPENROUTER_BASE_URL

logger = logging.getLogger(__name__)


def resolve_model_name(agent: str, override: str | None = None) -> str:
    """Model for an agent: UI override, then env (<AGENT>_MODEL), then default."""
    return (
        (override or "").strip()
        or os.getenv(f"{agent.upper()}_MODEL", "").strip()
        or DEFAULT_MODELS[agent]
    )


def get_model(agent: str, override: str | None = None) -> ChatOpenAI:
    model_name = resolve_model_name(agent, override)

    # [AI_APP_SEC_006] Use only LLMs from the organization's approved list — UNGUARDED:
    # [AI_APP_SEC_028] Do not use LLMs from the organization's disallowed list — UNGUARDED:
    # any model name from env or the UI sidebar is used as-is, with no allow/deny check.
    # LINEAJE: enforce() `agent` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:0dff70dfce10a9e1685bd855661da62849947e3585da8a7779e8f386923bc9ad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0dff70dfce10a9e1685bd855661da62849947e3585da8a7779e8f386923bc9ad', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        agent = _gr_client.enforce(_gr_site, agent, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
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
    # LINEAJE: enforce() `messages` at agent->llm pre_model — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:9a70cf15debdcd0fba77db6b2072f4fa684631a11b2c1062d9cf6d2fcc870f3a'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9a70cf15debdcd0fba77db6b2072f4fa684631a11b2c1062d9cf6d2fcc870f3a', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
    try:
        messages = _gr_client.enforce(_gr_site, messages, content_type='application/json', variable_name='messages', source_file=__file__, before_line=44)
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    response = model.invoke(messages)
    _log_io(agent, model.model_name, messages, response.content)
    # LINEAJE: enforce() `response` at llm->agent post_model — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:5e6dece3f628b8edb3577c61b453329bf6c7bac7b71c81744ce0f0def761ab2e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5e6dece3f628b8edb3577c61b453329bf6c7bac7b71c81744ce0f0def761ab2e', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='llm', destination_type='agent')
    try:
        response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=45)
    except _gr_client.GuardrailUnavailableError:
        pass
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
        # LINEAJE: enforce() `record` at agent->external data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:5eaba447e6af68eef7ad42d2d4d2c76f248869805052d59cc479762f54e10c3a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5eaba447e6af68eef7ad42d2d4d2c76f248869805052d59cc479762f54e10c3a', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external')
        try:
            record = _gr_client.enforce(_gr_site, record, content_type='application/json', variable_name='record', source_file=__file__, before_line=64)
        except _gr_client.GuardrailUnavailableError:
            pass
        f.write(json.dumps(record) + "\n")
