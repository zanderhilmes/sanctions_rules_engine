"""
AgeImprobabilityRule — clears alerts where the SDN sanction date predates the
customer's birth or the customer would have been implausibly young when sanctioned.

From the guide:
  Secondary clearing mechanism:
  "Date added to sanctions list — The Sanctioned individual was added to the
   list before the customer was born or shortly after
   (ie., seller was born in 1998, and individual was sanctioned in 2000)."

  Alternative Reviews:
  "Date SDN added to the watchlist is not possible to be the same person;
   age improbability, clear [F+ 1D]."

The guide classifies date-added as a SECONDARY mechanism (to be used alongside a
name or DOB mismatch). However, when the customer was not yet born at the time of
sanctioning, the evidence is so strong that this rule fires as a HARD CLEAR
(weight 0.90) even without a primary mismatch.  Age at sanctioning >= threshold
(default 5 years) produces only a soft CLEAR signal, consistent with its
secondary-mechanism status.

Requires:
  alert.customer_dob     — year extracted from customer DOB string
  alert.sdn_date_added   — year of sanction listing (from SDN Remarks or mock data)
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule
from sanctions.utils import parse_date

_HARD_CLEAR_WEIGHT = 0.90   # Customer not yet born when sanctioned
_SOFT_CLEAR_WEIGHT = 0.50   # Customer was very young (secondary mechanism)


class AgeImprobabilityRule(BaseRule):
    name = "age_improbability"
    weight = _HARD_CLEAR_WEIGHT
    priority = 16   # Runs just after DOB mismatch

    def __init__(self, age_improbability_max_years: int = 5) -> None:
        self.age_threshold = age_improbability_max_years

    def evaluate(self, alert: Alert) -> RuleFlag:
        if not alert.customer_dob:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="Customer DOB not available — age improbability check skipped",
            )

        if not alert.sdn_date_added:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="SDN date-added not available — age improbability check skipped",
            )

        customer_date = parse_date(alert.customer_dob)
        added_date = parse_date(alert.sdn_date_added)

        if customer_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse customer DOB '{alert.customer_dob}'",
            )
        if added_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse SDN date-added '{alert.sdn_date_added}'",
            )

        customer_birth_year = customer_date.year
        sdn_added_year = added_date.year
        age_at_sanctioning = sdn_added_year - customer_birth_year

        if age_at_sanctioning <= 0:
            # Customer was not yet born when the SDN was sanctioned — hard clear
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_HARD_CLEAR_WEIGHT,
                detail=(
                    f"SDN was added to watchlist in {sdn_added_year} but customer "
                    f"was born in {customer_birth_year} — age improbability, "
                    f"impossible to be the same person [F+ 1D]"
                ),
            )

        if age_at_sanctioning < self.age_threshold:
            # Customer was extremely young when sanctioned — soft secondary clear
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_SOFT_CLEAR_WEIGHT,
                detail=(
                    f"Customer would have been only {age_at_sanctioning} year(s) old "
                    f"when SDN was added ({sdn_added_year}); born {customer_birth_year} "
                    f"— age improbability, soft clear [F+ 1D] (secondary mechanism)"
                ),
            )

        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=(
                f"Customer would have been {age_at_sanctioning} years old when SDN "
                f"was added ({sdn_added_year}) — age is plausible, no clear signal"
            ),
        )
