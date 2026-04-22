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
    min_signup_age: int = 18    # Minimum age at account creation (used when customer_dob absent)
    dob_mismatch_high_score_threshold: float = 80.0   # Above this score, DOB mismatch routes to LLM instead of auto-clearing


class SnowflakeConfig(BaseModel):
    enabled: bool = False
    account: str = ""           # e.g. xy12345.us-east-1
    user: str = ""
    password: str = ""          # leave blank when using SSO/OAuth
    warehouse: str = ""
    database: str = "APP_CASH"
    schema_name: str = "HEALTH"
    table: str = "IDENTITY_IDV_ATTEMPTS"
    authenticator: str = "snowflake"  # "snowflake" | "externalbrowser" | "oauth" | Okta URL
    token: str = ""             # OAuth token (only used when authenticator=oauth)
    # Account creation date lookup (optional — leave account_table blank to skip)
    account_table: str = ""          # e.g. APP_CASH.CORE.SELLERS — fully qualified
    account_id_col: str = "CUSTOMER_TOKEN"
    account_created_col: str = "CREATED_AT"
    # DOB history table — richer source than IDV attempts (has full DOB date column)
    dob_history_table: str = "APP_CASH.HEALTH.IDENTITY_DOB_HISTORY"
    # Customer summary table — BIRTH_YEAR fallback when DOB history is absent
    customer_summary_table: str = "APP_CASH.APP.CUSTOMER_SUMMARY"
    # IDV address lookup — populates customer_state for the country mismatch rule.
    # Set to the column name in the IDV table that holds the customer's US state.
    # Leave blank to skip (rule will not fire until this is configured).
    # e.g. "STATE" or "RESIDENTIAL_STATE" depending on your schema.
    address_state_col: str = ""


class TLOConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""           # set via TLOXP_API_KEY env var
    api_url: str = ""           # set via TLOXP_API_URL env var
    timeout_seconds: int = 10
    max_retries: int = 2


class OFACConfig(BaseModel):
    # NOTE: Option 1 (preferred) — fix ERF_DOB in Bridger export settings.
    # Disable this enricher (enabled: false) once Bridger populates ERF_DOB.
    enabled: bool = False
    xml_url: str = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"
    cache_path: str = "data/sdn_advanced.xml"
    max_age_hours: int = 24
    timeout_seconds: int = 30


class OutputConfig(BaseModel):
    csv_path: str = "output/audit_trail.csv"
    json_path: str = "output/audit_trail.json"


class AppConfig(BaseModel):
    api_key: str = ""
    llm: LLMConfig = LLMConfig()
    rules: RulesConfig = RulesConfig()
    snowflake: SnowflakeConfig = SnowflakeConfig()
    tlo: TLOConfig = TLOConfig()
    ofac: OFACConfig = OFACConfig()
    output: OutputConfig = OutputConfig()


def load_config(config_path: str = "config.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        return AppConfig()
    with open(path) as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}
    resolved = _resolve_env_vars(raw)
    return AppConfig(**resolved)
