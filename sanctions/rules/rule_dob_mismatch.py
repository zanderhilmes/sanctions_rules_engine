"""
DOBMismatchRule — clears alerts where the customer DOB does not match the SDN DOB.

From the guide:
  "DOB evaluation, if unable to clear by Name"
  "Cash Customer DOB does not match SDN DOB DD/MM/YYYY → Clear - DOB Mismatch [F+ 1B]"
  "If SDN DOB is unknown, skip to Location."

This rule fires a HARD CLEAR (weight >= clear_hard_weight = 0.90) so it can
override a hard escalation from name_components.  This correctly implements the
guide's priority hierarchy: name match proceeds to DOB check, and a DOB mismatch
there still clears the alert regardless of how closely names matched.

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

_CLEAR_WEIGHT = 0.90   # Hard-clear weight — overrides name-match hard escalation


class DOBMismatchRule(BaseRule):
    name = "dob_mismatch"
    weight = _CLEAR_WEIGHT
    priority = 15   # Runs after name_components (5) and alias_match (6), before others

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

        # If either is year-only, compare years with ±1 tolerance
        if is_year_only(customer_date) or is_year_only(sdn_date):
            year_diff = abs(customer_date.year - sdn_date.year)
            if year_diff > 1:
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="CLEAR",
                    weight=_CLEAR_WEIGHT,
                    detail=(
                        f"Birth year mismatch: customer {customer_date.year} "
                        f"vs SDN {sdn_date.year} (diff={year_diff}y) — DOB mismatch [F+ 1B]"
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
                weight=_CLEAR_WEIGHT,
                detail=(
                    f"DOB mismatch: customer {customer_date.isoformat()} "
                    f"vs SDN {sdn_date.isoformat()} — [F+ 1B]"
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
