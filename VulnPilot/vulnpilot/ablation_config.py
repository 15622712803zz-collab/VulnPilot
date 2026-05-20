"""Runtime switches for ablation experiments.

The defaults keep the original project behavior unchanged.  Set the
environment variables below to "false"/"0"/"no"/"off" to disable modules:

- ENABLE_PROCESS_NOTEBOOK
- ENABLE_SKILLS
"""

from __future__ import annotations

import os


FALSE_VALUES = {"0", "false", "no", "off", "disabled"}


def _env_enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in FALSE_VALUES


def process_notebook_enabled() -> bool:
    """Whether ProcessNotebook injection and updates are enabled."""
    return _env_enabled("ENABLE_PROCESS_NOTEBOOK", True)


def skills_enabled() -> bool:
    """Whether SKILL.md knowledge loading is enabled."""
    return _env_enabled("ENABLE_SKILLS", True)


def ablation_config_summary() -> dict[str, str]:
    """Small serializable summary for logs and reports."""
    return {
        "ENABLE_PROCESS_NOTEBOOK": "true" if process_notebook_enabled() else "false",
        "ENABLE_SKILLS": "true" if skills_enabled() else "false",
    }
