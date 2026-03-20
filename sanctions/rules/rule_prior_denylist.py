"""
PriorDenylistRule — hard-escalates alerts where the customer was previously
denylisted for sanctions in Notary.

From the guide:
  "If the account was previously denylisted by the Sanctions team or has the
   Sanctions Adversity Hold (aka Cash Flow Hold) applied due to a previous
   review, the account can be actioned as 'Do Not Clear' and not escalated to
   a L2 review."

Implementation:
  Prior denylist → ESCALATE (weight 0.95, hard escalate) so the alert is
  immediately routed to human review rather than auto-cleared, even if all
  other rules suggest a false positive.  The reviewer can then confirm the
  prior decision context.

Requires:
  alert.prior_sanctions_denylist = True
  (set by NotaryEnricher when Notary case history contains a DENYLISTED entry
  in a sanctions queue)
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule


class PriorDenylistRule(BaseRule):
    name = "prior_sanctions_denylist"
    weight = 0.95   # Hard-escalate weight
    priority = 3    # Runs very early — no point scoring other rules if this fires

    def evaluate(self, alert: Alert) -> RuleFlag:
        if alert.prior_sanctions_denylist:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="ESCALATE",
                weight=0.95,
                detail=(
                    "Customer has a prior sanctions denylist entry in Notary — "
                    "Do Not Clear without L2 review per policy"
                ),
            )
        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail="No prior sanctions denylist found in Notary",
        )
