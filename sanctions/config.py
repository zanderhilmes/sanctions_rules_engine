"""
Typed config loader for the sanctions rules engine.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict

import yaml
from pydantic import BaseModel


def _resolve_env_vars(value):
    if isinstance(value, str):
        def replacer(match):
            var = match.group(1)
            result = os.environ.get(var, "")
            return result if result else match.group(0)
        return re.sub(r"\$\{([^}]+)\}", replacer, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(i) for i in value]
    return value


class LLMConfig(BaseModel):
    model: str = "claude-haiku-4-5-20251001"
    escalation_model: str = "claude-sonnet-4-6"
    strong_model_score_threshold: float = 70.0
    max_tokens: int = 512


class RulesConfig(BaseModel):
    auto_clear_confidence_threshold: float = 0.65
    escalate_hard_weight: float = 0.90
    clear_hard_weight: float = 0.90
    low_score_clear_threshold: float = 30.0
    common_names_file: str = "data/common_names.txt"
    age_improbability_max_years: int = 5


class OutputConfig(BaseModel):
    csv_path: str = "output/audit_trail.csv"
    json_path: str = "output/audit_trail.json"


class AppConfig(BaseModel):
    api_key: str = ""
    llm: LLMConfig = LLMConfig()
    rules: RulesConfig = RulesConfig()
    output: OutputConfig = OutputConfig()


def load_config(config_path: str = "config.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        return AppConfig()
    with open(path) as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}
    resolved = _resolve_env_vars(raw)
    return AppConfig(**resolved)
