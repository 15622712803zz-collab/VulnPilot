"""Unit tests for the auditor agent."""

import json
import sys
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, ToolMessage

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from vulnpilot.agents.auditor_agent import auditor_node, create_auditor_prompt


def tool_message(content: str, name: str) -> ToolMessage:
    """Create a ToolMessage compatible with current LangChain versions."""
    return ToolMessage(content=content, name=name, tool_call_id=f"{name}_test")


class FakeLLM:
    def __init__(self, payload: dict):
        self.payload = payload

    async def ainvoke(self, messages):
        return AIMessage(content=json.dumps(self.payload))


def install_fake_auditor(monkeypatch: pytest.MonkeyPatch, payload: dict) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    def fake_create_model(config):
        return FakeLLM(payload)

    monkeypatch.setattr("vulnpilot.model.create_model", fake_create_model)


@pytest.mark.asyncio
async def test_auditor_code_error_syntax(monkeypatch):
    install_fake_auditor(
        monkeypatch,
        {
            "error_type": "code_error",
            "confidence": 0.9,
            "next_action": "regenerate_code",
            "reasoning": "SyntaxError indicates generated PoC code is invalid.",
            "key_evidence": ["SyntaxError"],
            "suggested_fix": "Regenerate the Python PoC.",
        },
    )
    state = {
        "messages": [
            tool_message("SyntaxError: invalid syntax", "execute_python_poc"),
            tool_message("SyntaxError: invalid syntax at line 15", "execute_python_poc"),
            tool_message("SyntaxError: EOL while scanning string literal", "execute_python_poc"),
        ],
        "consecutive_failures": 3,
        "audit_history": [],
        "max_audit_retries": 2,
    }

    result = await auditor_node(state)
    error_context = result["current_error_context"]

    assert error_context["error_type"] == "code_error"
    assert error_context["next_action"] == "regenerate_code"
    assert error_context["confidence"] >= 0.8


@pytest.mark.asyncio
async def test_auditor_code_error_command(monkeypatch):
    install_fake_auditor(
        monkeypatch,
        {
            "error_type": "code_error",
            "confidence": 0.88,
            "next_action": "regenerate_code",
            "reasoning": "The command is not available on the system.",
            "key_evidence": ["command not found"],
            "suggested_fix": "Generate a valid command.",
        },
    )
    state = {
        "messages": [
            tool_message("sh: nmappp: command not found", "execute_command"),
            tool_message("bash: sqlma: No such file or directory", "execute_command"),
            tool_message("command not found: dirbuster", "execute_command"),
        ],
        "consecutive_failures": 3,
        "audit_history": [],
        "max_audit_retries": 2,
    }

    result = await auditor_node(state)
    error_context = result["current_error_context"]

    assert error_context["error_type"] == "code_error"
    assert error_context["next_action"] == "regenerate_code"


@pytest.mark.asyncio
async def test_auditor_decision_error_no_progress(monkeypatch):
    install_fake_auditor(
        monkeypatch,
        {
            "error_type": "decision_error",
            "confidence": 0.86,
            "next_action": "consult_advisor",
            "reasoning": "Repeated identical responses indicate no progress.",
            "key_evidence": ["same response length"],
            "suggested_fix": "Re-plan the attack path.",
        },
    )
    state = {
        "messages": [
            tool_message("Status: 200; Length: 317; Content: login form", "execute_python_poc"),
            tool_message("Status: 200; Length: 317; Content: login form", "execute_python_poc"),
            tool_message("Status: 200; Length: 317; Content: login form", "execute_python_poc"),
        ],
        "consecutive_failures": 3,
        "audit_history": [],
        "max_audit_retries": 2,
    }

    result = await auditor_node(state)
    error_context = result["current_error_context"]

    assert error_context["error_type"] == "decision_error"
    assert error_context["next_action"] == "consult_advisor"


@pytest.mark.asyncio
async def test_auditor_decision_error_ignored_hint(monkeypatch):
    install_fake_auditor(
        monkeypatch,
        {
            "error_type": "decision_error",
            "confidence": 0.84,
            "next_action": "consult_advisor",
            "reasoning": "The agent ignored an explicit password-format hint.",
            "key_evidence": ["password is four digits"],
            "suggested_fix": "Use the hint to constrain the search.",
        },
    )
    state = {
        "messages": [
            tool_message("Response: password is four digits. Status: 200", "execute_python_poc"),
            tool_message("Tried SQL injection, still received the password hint.", "execute_python_poc"),
            tool_message("Tried XSS, still received the password hint.", "execute_python_poc"),
        ],
        "consecutive_failures": 3,
        "audit_history": [],
        "max_audit_retries": 2,
    }

    result = await auditor_node(state)
    error_context = result["current_error_context"]

    assert error_context["error_type"] == "decision_error"
    assert error_context["next_action"] == "consult_advisor"


@pytest.mark.asyncio
async def test_create_auditor_prompt():
    state = {
        "messages": [
            tool_message("error one", "tool1"),
            tool_message("error two", "tool2"),
            tool_message("error three", "tool3"),
        ],
        "consecutive_failures": 3,
        "audit_history": [],
    }

    context = create_auditor_prompt(state)

    assert "error one" in context
    assert "error two" in context
    assert "error three" in context
    assert "tool1" in context
    assert "tool2" in context
    assert "tool3" in context