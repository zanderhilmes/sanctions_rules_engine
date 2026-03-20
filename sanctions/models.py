"""
Core Pydantic data models for the sanctions compliance pipeline.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    AUTO_CLEAR = "AUTO_CLEAR"
    ESCALATE = "ESCALATE"
    PENDING = "PENDING"


class Alert(BaseModel):
    """Incoming alert from the screening system."""
    alert_id: str
    account_id: Optional[str] = None        # Internal account identifier (links to Snowflake)
    customer_name: str
    sdn_name: str
    match_score: float = Field(ge=0.0, le=100.0)
    zip_code: Optional[str] = None
    customer_dob: Optional[str] = None      # "YYYY-MM-DD" from screening system or enrichment
    customer_verified: bool = False         # True if IDV-verified or confirmed by Notary/TLOxp

    # Populated by SDNEnricher
    sdn_type: Optional[str] = None          # e.g. "individual", "entity", "vessel"
    sdn_country: Optional[str] = None       # ISO-2 or country name from SDN list
    sdn_program: Optional[str] = None       # e.g. "SDGT", "IRAN", "CUBA"
    sdn_aliases: List[str] = Field(default_factory=list)
    customer_state: Optional[str] = None    # Derived from zip_code
    sdn_dob: Optional[str] = None           # Parsed from SDN Remarks field
    sdn_date_added: Optional[str] = None    # Parsed from SDN Remarks if present

    # Populated by NotaryEnricher (when enabled)
    customer_email: Optional[str] = None    # Email address from Notary case record
    customer_ssn_confirmed: bool = False    # SSN is on file in Notary (value never stored)
    prior_sanctions_denylist: bool = False  # Customer was previously denylisted for sanctions
    notary_hit: Optional[bool] = None       # True/False/None = hit / not found / not queried

    # Populated by TLOxpEnricher (when enabled)
    tlo_dob: Optional[str] = None           # DOB returned by TLOxp
    tlo_state: Optional[str] = None         # State confirmed by TLOxp
    tlo_hit: Optional[bool] = None          # True/False/None = hit / not found / not queried


class RuleFlag(BaseModel):
    """Output from a single rule evaluation."""
    rule_name: str
    triggered: bool
    direction: Optional[str] = None         # "CLEAR" | "ESCALATE" | None
    weight: float = 0.0
    detail: str = ""


class Disposition(BaseModel):
    """Aggregated outcome from rule engine + optional LLM."""
    decision: Decision
    confidence: float = 0.0                 # 0.0–1.0
    rule_flags: List[RuleFlag] = Field(default_factory=list)
    llm_called: bool = False
    llm_rationale: Optional[str] = None
    llm_model: Optional[str] = None


class AuditRecord(BaseModel):
    """Flattened record written to audit trail CSV/JSON."""
    alert_id: str
    customer_name: str
    sdn_name: str
    match_score: float
    zip_code: Optional[str]
    customer_dob: Optional[str]
    sdn_dob: Optional[str]
    notary_hit: Optional[bool]
    tlo_hit: Optional[bool]
    customer_email: Optional[str]
    sdn_type: Optional[str]
    sdn_country: Optional[str]
    customer_state: Optional[str]
    decision: str
    confidence: float
    rule_summary: str                       # Pipe-separated triggered rule names
    llm_called: bool
    llm_rationale: Optional[str]
    llm_model: Optional[str]
    processed_at: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def from_alert_and_disposition(
        cls, alert: Alert, disposition: Disposition
    ) -> "AuditRecord":
        triggered = [
            f.rule_name for f in disposition.rule_flags if f.triggered
        ]
        return cls(
            alert_id=alert.alert_id,
            customer_name=alert.customer_name,
            sdn_name=alert.sdn_name,
            match_score=alert.match_score,
            zip_code=alert.zip_code,
            customer_dob=alert.customer_dob,
            sdn_dob=alert.sdn_dob,
            notary_hit=alert.notary_hit,
            tlo_hit=alert.tlo_hit,
            customer_email=alert.customer_email,
            sdn_type=alert.sdn_type,
            sdn_country=alert.sdn_country,
            customer_state=alert.customer_state,
            decision=disposition.decision.value,
            confidence=round(disposition.confidence, 4),
            rule_summary="|".join(triggered) if triggered else "none",
            llm_called=disposition.llm_called,
            llm_rationale=disposition.llm_rationale,
            llm_model=disposition.llm_model,
        )
