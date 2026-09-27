"""LangGraph workflow for the support ticket operator.

intake -> triage_agent -> resolver_agent -> respond
"""

import json
import logging
from typing import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

import llm
from config.constants import TICKET_CATEGORIES, TICKET_PRIORITIES

_ai_app_sec_006_DISAPPROVED_MODELS = {
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
}


def _ai_app_sec_006_normalize_model_identifier(model_name: str) -> str:
    return "".join(ch for ch in model_name.lower() if ch.isalnum())


def _ai_app_sec_006_validate_model(model_name: str | None) -> str | None:
    if model_name is None:
        return None
    if _ai_app_sec_006_normalize_model_identifier(model_name) in _ai_app_sec_006_DISAPPROVED_MODELS:
        raise ValueError(f"Disapproved model override: {model_name}")
    return model_name

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

    _ai_app_sec_006_model_override = _ai_app_sec_006_validate_model(state.get("model_overrides", {}).get("triage"))
    text, model_name = llm.invoke("triage", [system, user], _ai_app_sec_006_model_override)
    try:
        parsed = json.loads(text.strip().removeprefix("```json").removesuffix("```"))
    except json.JSONDecodeError:
        logger.warning("triage returned non-JSON output; defaulting")
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

    _ai_app_sec_006_model_override = _ai_app_sec_006_validate_model(state.get("model_overrides", {}).get("resolver"))
    text, model_name = llm.invoke("resolver", [system, user], _ai_app_sec_006_model_override)
    return {"reply": text, "models_used": {**state["models_used"], "resolver": model_name}}


def respond(state: TicketState) -> TicketState:
    logger.info(
        "ticket resolved category=%s priority=%s models=%s",
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
