"""
MissingDOBRule — flags alerts where no customer date-of-birth is available.

Rationale: absence of DOB removes the most powerful identity-disambiguation signal
(F+ 1B — DOB mismatch).  A customer with no DOB on record cannot be cleared on
date-of-birth grounds, so the absence itself is a compliance risk signal.

This rule fires a soft ESCALATE vote (weight=0.30, below the hard-escalate threshold
of 0.90).  In the registry, soft ESCALATE votes are subtracted from the cumulative
clear_score, reducing auto-clear confidence without forcing a mandatory escalation:

  - Clear-leaning signals alone (e.g. geography=0.35, common_name=0.45) will no longer
    reach the 0.65 auto-clear threshold when DOB is missing.
  - Strong clear signals (e.g. low_score=0.60 + geography=0.35 → 0.95) are still
    dampened: 0.95 − 0.30 = 0.65, right at the threshold — outcome depends on other signals.
  - Hard clears (DOB mismatch, age improbability at weight=0.90) are unaffected — they
    bypass the score accumulation entirely.

Only fires when customer_dob is absent; does not fire when DOB is populated (even
year-only, which is sufficient for the DOB mismatch and age improbability checks).
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

_ESCALATE_WEIGHT = 0.30


class MissingDOBRule(BaseRule):
    name = "missing_dob"
    weight = _ESCALATE_WEIGHT
    priority = 17   # Runs after dob_mismatch (15) and age_improbability (16)

    def evaluate(self, alert: Alert) -> RuleFlag:
        if not alert.customer_dob:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="ESCALATE",
                weight=_ESCALATE_WEIGHT,
                detail="No customer DOB on record — identity cannot be cleared on date-of-birth grounds",
            )
        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=_ESCALATE_WEIGHT,
            detail=f"Customer DOB present ({alert.customer_dob}) — no missing-DOB risk signal",
        )
