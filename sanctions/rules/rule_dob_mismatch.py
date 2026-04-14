"""
DOBMismatchRule — clears alerts where the customer DOB does not match the SDN DOB.

From the guide:
  "DOB evaluation, if unable to clear by Name"
  "Cash Customer DOB does not match SDN DOB DD/MM/YYYY → Clear - DOB Mismatch [F+ 1B]"
  "If SDN DOB is unknown, skip to Location."

Weight behaviour depends on the Bridger match score:

  match_score < high_score_threshold (default 80):
    → HARD CLEAR (weight=0.90) — overrides name-match hard escalation and auto-clears.
      At low scores the name similarity is already weak, so DOB mismatch is decisive.

  match_score >= high_score_threshold:
    → CONTESTED CLEAR (weight=0.75) — strong clearing signal but not a hard override.
      The registry detects the combination of hard ESCALATE (name match) + contested
      CLEAR (DOB mismatch) and routes to PENDING → LLM for human-in-the-loop review.
      When the name match is very close, a DOB discrepancy alone should not auto-clear.

Comparison logic:
  - If both DOBs parse to full dates     → compare exact day/month/year
  - If either is year-only ("1960")      → compare years with ±1 tolerance
      |year_diff| > 1  → CLEAR (F+ 1B) — confirmed mismatch
      |year_diff| <= 1 → no signal      — within data-quality tolerance
  - Either DOB unavailable               → no signal (guide: skip to Location)

The ±1 year tolerance on year-only comparisons accounts for common data-entry
errors and different calendar/year-cutoff conventions in source systems.
"""
from __future__ import annotations

from datetime import date
from typing import Optional

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule
from sanctions.utils import is_year_only, parse_date

_HARD_CLEAR_WEIGHT      = 0.90   # Low match score — decisive, overrides hard escalation
_CONTESTED_CLEAR_WEIGHT = 0.75   # High match score — strong signal, but routes to LLM


class DOBMismatchRule(BaseRule):
    name = "dob_mismatch"
    weight = _HARD_CLEAR_WEIGHT
    priority = 15   # Runs after name_components (5) and alias_match (6), before others

    def __init__(self, high_score_threshold: float = 80.0) -> None:
        self.high_score_threshold = high_score_threshold

    def evaluate(self, alert: Alert) -> RuleFlag:
        customer_dob_str = alert.customer_dob
        sdn_dob_str = alert.sdn_dob

        if not customer_dob_str:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="Customer DOB not available — DOB check skipped",
            )

        if not sdn_dob_str:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="SDN DOB not available — skipping to Location per guide",
            )

        customer_date = parse_date(customer_dob_str)
        sdn_date = parse_date(sdn_dob_str)

        if customer_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse customer DOB '{customer_dob_str}' — DOB check skipped",
            )
        if sdn_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse SDN DOB '{sdn_dob_str}' — DOB check skipped",
            )

        # Choose weight based on match score
        clear_weight = (
            _CONTESTED_CLEAR_WEIGHT
            if alert.match_score >= self.high_score_threshold
            else _HARD_CLEAR_WEIGHT
        )
        routing_note = (
            "contested → LLM review"
            if clear_weight < _HARD_CLEAR_WEIGHT
            else "hard clear [F+ 1B]"
        )

        # If either is year-only, compare years with ±1 tolerance
        if is_year_only(customer_date) or is_year_only(sdn_date):
            year_diff = abs(customer_date.year - sdn_date.year)
            if year_diff > 1:
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="CLEAR",
                    weight=clear_weight,
                    detail=(
                        f"Birth year mismatch: customer {customer_date.year} "
                        f"vs SDN {sdn_date.year} (diff={year_diff}y, score={alert.match_score:.0f}) "
                        f"— DOB mismatch [F+ 1B] ({routing_note})"
                    ),
                )
            # Within ±1 year — could be data-entry error; treat as inconclusive
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=(
                    f"Birth years within 1-year tolerance: customer {customer_date.year} "
                    f"vs SDN {sdn_date.year} — inconclusive"
                ),
            )

        # Both are full dates — compare exactly
        if customer_date != sdn_date:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=clear_weight,
                detail=(
                    f"DOB mismatch: customer {customer_date.isoformat()} "
                    f"vs SDN {sdn_date.isoformat()} (score={alert.match_score:.0f}) "
                    f"— [F+ 1B] ({routing_note})"
                ),
            )

        # DOBs match — name AND DOB match is strong, escalation continues
        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=(
                f"DOB matches: {customer_date.isoformat()} — "
                f"name and DOB match, proceeding to Alternative Reviews"
            ),
        )
