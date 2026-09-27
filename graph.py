"""LangGraph workflow for the support ticket operator.

intake -> triage_agent -> resolver_agent -> respond
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


import json
import logging
from typing import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

import llm
from config.constants import TICKET_CATEGORIES, TICKET_PRIORITIES

logger = logging.getLogger(__name__)


class TicketState(TypedDict, total=False):
    ticket_text: str
    model_overrides: dict[str, str]
    category: str
    priority: str
    reply: str
    models_used: dict[str, str]


def intake(state: TicketState) -> TicketState:
    ticket_text = state["ticket_text"].strip()

    # [AI_DAT_SEC_010] Do not log PII — UNGUARDED: the raw ticket (SSN, email,
    # phone, card number) is written to the application log as-is.
    # LINEAJE: enforce() `ticket_text` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:78f0abe482fc2373ace2fda626c4ee7ec260e4599d3d4d85ecbade02da8eb185'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:78f0abe482fc2373ace2fda626c4ee7ec260e4599d3d4d85ecbade02da8eb185', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        ticket_text = _gr_client.enforce(_gr_site, ticket_text, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("ticket intake text=%s", ticket_text)

    return {"ticket_text": ticket_text, "models_used": {}}


def triage_agent(state: TicketState) -> TicketState:
    system = SystemMessage(
        "You are a support triage agent. Classify the ticket. Respond with JSON only: "
        f'{{"category": one of {TICKET_CATEGORIES}, "priority": one of {TICKET_PRIORITIES}}}'
    )
    # [AI_DAT_SEC_011] Do not send PII to AI Models — UNGUARDED: the raw ticket
    # including PII is sent to the model.
    user = HumanMessage(state["ticket_text"])

    _lineaje_payload = "triage"
    # LINEAJE: enforce() `_lineaje_payload` at agent->llm pre_model — scan flagged AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:703f8dbff3956d86e1eb29c800aa73e8c0c2a3111871b70ab07c4f5b5ffdfdd2'
    _lineaje__lineaje_payload_evidence = {'_lineaje_payload': _lineaje_payload, 'model': (__import__("os").getenv("OPENROUTER_MODEL") or __import__("os").getenv("LLM_MODEL") or "")}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:703f8dbff3956d86e1eb29c800aa73e8c0c2a3111871b70ab07c4f5b5ffdfdd2', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
    try:
        _lineaje__lineaje_payload_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_payload_evidence, content_type='application/json')
        _lineaje_payload = _lineaje__lineaje_payload_evidence.get('_lineaje_payload', _lineaje_payload) if isinstance(_lineaje__lineaje_payload_evidence, dict) else _lineaje_payload
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    text, model_name = llm.invoke(_lineaje_payload, [system, user], state.get("model_overrides", {}).get("triage"))
    try:
        parsed = json.loads(text.strip().removeprefix("```json").removesuffix("```"))
    except json.JSONDecodeError:
        _lineaje_payload = "triage returned non-JSON output; defaulting"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM); AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:3b1e888720ec3513481bc7cbfa34bbb5d346533c2aa0956f98ee53b230ccbd04'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3b1e888720ec3513481bc7cbfa34bbb5d346533c2aa0956f98ee53b230ccbd04', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.warning(_lineaje_payload)
        parsed = {}

    return {
        "category": parsed.get("category", "other"),
        "priority": parsed.get("priority", "medium"),
        "models_used": {**state["models_used"], "triage": model_name},
    }


def resolver_agent(state: TicketState) -> TicketState:
    system = SystemMessage(
        "You are a helpful customer support agent. Write a short, friendly reply to the "
        "customer that summarizes their issue and the next steps. "
        f"Ticket category: {state['category']}, priority: {state['priority']}."
    )
    # [AI_DAT_SEC_011] Do not send PII to AI Models — UNGUARDED: the raw ticket
    # including PII is sent to the model.
    user = HumanMessage(state["ticket_text"])

    _lineaje_payload = "resolver"
    # LINEAJE: enforce() `_lineaje_payload` at agent->llm pre_model — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:7024fde14533f3c9d7cb16ea3245d49c78849aa260f92faf590a1db00225cb9f'
    _lineaje__lineaje_payload_evidence = {'_lineaje_payload': _lineaje_payload, 'model': (__import__("os").getenv("OPENROUTER_MODEL") or __import__("os").getenv("LLM_MODEL") or "")}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7024fde14533f3c9d7cb16ea3245d49c78849aa260f92faf590a1db00225cb9f', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
    try:
        _lineaje__lineaje_payload_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_payload_evidence, content_type='application/json')
        _lineaje_payload = _lineaje__lineaje_payload_evidence.get('_lineaje_payload', _lineaje_payload) if isinstance(_lineaje__lineaje_payload_evidence, dict) else _lineaje_payload
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    text, model_name = llm.invoke(_lineaje_payload, [system, user], state.get("model_overrides", {}).get("resolver"))
    return {"reply": text, "models_used": {**state["models_used"], "resolver": model_name}}


def respond(state: TicketState) -> TicketState:
    _lineaje_payload = "ticket resolved category=%s priority=%s models=%s"
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM); AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:b3a3f972a930390b3980737cb3a3f85fc48135485f56cb12cfc4ab5b8ca3375d'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b3a3f972a930390b3980737cb3a3f85fc48135485f56cb12cfc4ab5b8ca3375d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info(
        _lineaje_payload,
        state["category"], state["priority"], state["models_used"],
    )
    return {}


def build_graph():
    graph = StateGraph(TicketState)
    graph.add_node("intake", intake)
    graph.add_node("triage_agent", triage_agent)
    graph.add_node("resolver_agent", resolver_agent)
    graph.add_node("respond", respond)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "triage_agent")
    graph.add_edge("triage_agent", "resolver_agent")
    graph.add_edge("resolver_agent", "respond")
    graph.add_edge("respond", END)
    return graph.compile()


_GRAPH = None


def run_ticket(ticket_text: str, model_overrides: dict[str, str] | None = None) -> TicketState:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH.invoke({"ticket_text": ticket_text, "model_overrides": model_overrides or {}})
