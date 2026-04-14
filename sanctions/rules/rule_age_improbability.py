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
name or DOB mismatch). However, when the customer was not yet born or was an infant (age <= 2) at the time of
sanctioning, the evidence is so strong that this rule fires as a HARD CLEAR
(weight 0.90) even without a primary mismatch.  Age at sanctioning >= threshold
(default 5 years) produces only a soft CLEAR signal, consistent with its
secondary-mechanism status.

Primary mode (customer_dob available):
  Compares actual customer birth year to SDN date-added year.

Fallback mode (customer_dob absent but account_created_at available):
  Derives the LATEST POSSIBLE birth year from the account creation date:
    latest_birth_year = account_created_year - min_signup_age (default 18)
  Uses this as a conservative proxy — only clears if even the YOUNGEST possible
  customer couldn't have been the SDN at the time of sanctioning.
  Weights are identical since the logic is equally sound: impossible vs. improbable.

Requires:
  alert.sdn_date_added      — year of sanction listing (from OFAC XML or mock data)
  alert.customer_dob        — customer birth year (primary); OR
  alert.account_created_at  — account creation date (fallback proxy)
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

    def __init__(
        self,
        age_improbability_max_years: int = 5,
        min_signup_age: int = 18,
    ) -> None:
        self.age_threshold = age_improbability_max_years
        self.min_signup_age = min_signup_age

    def evaluate(self, alert: Alert) -> RuleFlag:
        if not alert.sdn_date_added:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="SDN date-added not available — age improbability check skipped",
            )

        added_date = parse_date(alert.sdn_date_added)
        if added_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse SDN date-added '{alert.sdn_date_added}'",
            )

        # ---- Primary mode: use actual customer DOB ----
        if alert.customer_dob:
            return self._evaluate_with_birth_year(
                alert, added_date.year, alert.customer_dob, mode="dob"
            )

        # ---- Fallback mode: derive latest-possible birth year from account creation ----
        if alert.account_created_at:
            acct_date = parse_date(alert.account_created_at)
            if acct_date is not None:
                latest_birth_year = acct_date.year - self.min_signup_age
                return self._evaluate_with_birth_year(
                    alert, added_date.year, str(latest_birth_year), mode="account_creation"
                )

        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail="Neither customer_dob nor account_created_at available — skipped",
        )

    def _evaluate_with_birth_year(
        self,
        alert: Alert,
        sdn_added_year: int,
        birth_year_str: str,
        mode: str,
    ) -> RuleFlag:
        birth_date = parse_date(birth_year_str)
        if birth_date is None:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"Could not parse birth year '{birth_year_str}'",
            )

        birth_year = birth_date.year
        age_at_sanctioning = sdn_added_year - birth_year
        proxy_note = (
            f" (proxy: account created {alert.account_created_at}, "
            f"min signup age {self.min_signup_age})"
            if mode == "account_creation" else ""
        )

        if age_at_sanctioning <= 2:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_HARD_CLEAR_WEIGHT,
                detail=(
                    f"SDN was added to watchlist in {sdn_added_year} but customer "
                    f"was born in {birth_year}{proxy_note} — age improbability, "
                    f"impossible to be the same person [F+ 1D] "
                    f"(age at sanctioning: {age_at_sanctioning})"
                ),
            )

        if age_at_sanctioning < self.age_threshold:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_SOFT_CLEAR_WEIGHT,
                detail=(
                    f"Customer would have been only {age_at_sanctioning} year(s) old "
                    f"when SDN was added ({sdn_added_year}){proxy_note}; "
                    f"born {birth_year} — age improbability, soft clear [F+ 1D]"
                ),
            )

        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=(
                f"Customer would have been {age_at_sanctioning} years old when SDN "
                f"was added ({sdn_added_year}){proxy_note} — age is plausible"
            ),
        )
