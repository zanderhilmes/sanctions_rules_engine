"""
AliasMatchRule — checks the customer name against all SDN aliases.

From the guide: "Make sure the alias does not match as well."

A name mismatch against the primary SDN name is NOT sufficient to clear if
any alias matches. This rule fires HARD ESCALATE (weight 0.95) when the
customer name tokens match any SDN alias using the same token-set logic as
NameComponentRule.

Weight 0.95 (hard escalate) ensures alias matches always route through the
registry's contested or escalation paths:
  - Alias match + hard DOB mismatch (weight 0.90 CLEAR): hard clear takes
    registry priority 1 → AUTO_CLEAR. A decisive DOB gap still clears.
  - Alias match + contested DOB mismatch (weight 0.75, high score + unverified):
    hard_escalate + max_clear (0.75) >= contested threshold (0.70) → PENDING → LLM.
    LLM adjudicates when an alias matches and DOB is unverified.
  - Alias match + no DOB: hard escalate alone → ESCALATE.

Previously used weight 0.80 (soft escalate), which only subtracted from
clear_score without setting hard_escalate. This allowed cases to AUTO_CLEAR
when name_components (0.85) and dob_mismatch (0.75) together outweighed the
soft penalty: 0.85 - 0.80 + 0.75 = 0.80 >= 0.65 threshold, bypassing LLM
entirely despite an alias match.

Alias matching cases (mirrors NameComponentRule):
  - Customer tokens == alias tokens (any order) → ESCALATE
  - All customer tokens ⊆ alias tokens (alias has extra particles/words) → ESCALATE
  - Customer tokens ⊃ alias tokens → no match (customer name is more specific)

Requires sdn_aliases to be populated by SDNEnricher; if aliases list is empty
(e.g. SDN files not loaded), the rule produces no signal.
"""
from __future__ import annotations

from typing import FrozenSet, List

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule
from sanctions.rules.rule_name_components import _tokenize

_ESCALATE_WEIGHT = 0.95  # Hard escalate — alias match always routes to LLM or escalation


class AliasMatchRule(BaseRule):
    """
    Escalates if the customer name matches any SDN alias.
    Must run after enrichment has populated alert.sdn_aliases.
    Priority 6 — runs immediately after NameComponentRule.
    """
    name = "alias_match"
    weight = _ESCALATE_WEIGHT
    priority = 6

    def evaluate(self, alert: Alert) -> RuleFlag:
        if not alert.sdn_aliases:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="No SDN aliases available (SDN files not loaded or no aliases on record)",
            )

        customer_tokens = _tokenize(alert.customer_name)
        if not customer_tokens:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="Empty customer name — cannot evaluate alias comparison",
            )

        for alias in alert.sdn_aliases:
            alias_tokens = _tokenize(alias)
            if not alias_tokens:
                continue

            # Exact token-set match (any order)
            if customer_tokens == alias_tokens:
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="ESCALATE",
                    weight=_ESCALATE_WEIGHT,
                    detail=(
                        f"Customer name tokens exactly match SDN alias '{alias}' "
                        f"— escalating per alias-check requirement"
                    ),
                )

            # Customer tokens are a subset of alias tokens
            # (alias has extra particles, e.g. "AL", "BIN", "ABU")
            if customer_tokens.issubset(alias_tokens):
                extra = alias_tokens - customer_tokens
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="ESCALATE",
                    weight=_ESCALATE_WEIGHT,
                    detail=(
                        f"Customer name tokens found in SDN alias '{alias}' "
                        f"(alias has extra tokens: {sorted(extra)}) — escalating"
                    ),
                )

        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=(
                f"Customer name does not match any of {len(alert.sdn_aliases)} "
                f"SDN alias(es) — no alias escalation signal"
            ),
        )
