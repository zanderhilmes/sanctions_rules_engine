"""
NameComponentRule — implements the three-case name token decision table from the
Watchlist Analyst User Guide.

Decision table (order-independent token-set comparison):

  Case 1 — Equal token counts
    All tokens match   → ESCALATE (weight 0.95, hard-escalate)
    Not all match      → CLEAR   (weight 0.85, F+ 1A)

  Case 2 — Customer has MORE tokens than SDN
    → CLEAR (weight 0.85, F+ 1A)
    Rationale: extra tokens indicate a different person.

  Case 3 — SDN has MORE tokens than customer
    All customer tokens found in SDN tokens → ESCALATE (weight 0.95)
    Not all customer tokens in SDN tokens   → CLEAR   (weight 0.85, F+ 1A)

Name normalization before comparison:
  - Lowercase + uppercase normalization (case-insensitive)
  - Hyphens, periods, commas replaced with spaces (e.g. "AL-RASHID" → "AL RASHID")
  - Other punctuation stripped
  - Empty tokens discarded

Note on name order: "George Michael Stevens" vs "Michael George Stevens" is treated
as an exact match (same token set) — consistent with guide Case 1 examples.
"""
from __future__ import annotations

import re
from typing import FrozenSet

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

_CLEAR_WEIGHT = 0.85    # Exceeds auto_clear threshold (0.65) on its own
_ESCALATE_WEIGHT = 0.95  # Exceeds escalate_hard_weight (0.90) → hard escalate


def _tokenize(name: str) -> FrozenSet[str]:
    """Normalize and return frozenset of uppercase tokens."""
    # Replace hyphens, periods, commas with spaces to split compound names
    normalized = re.sub(r"[-.,/]", " ", name)
    # Strip remaining non-alphanumeric/non-space characters
    normalized = re.sub(r"[^\w\s]", "", normalized)
    return frozenset(t.upper() for t in normalized.split() if t)


class NameComponentRule(BaseRule):
    """
    Core name token comparison rule derived from the analyst decision table.
    Priority 5 — runs first; its signal is the strongest single indicator.
    """
    name = "name_components"
    weight = 0.85   # Class-level default; overridden per-direction in flags
    priority = 5

    def evaluate(self, alert: Alert) -> RuleFlag:
        customer_tokens = _tokenize(alert.customer_name)
        sdn_tokens = _tokenize(alert.sdn_name)

        customer_count = len(customer_tokens)
        sdn_count = len(sdn_tokens)

        if customer_count == 0 or sdn_count == 0:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="Empty name — cannot evaluate token comparison",
            )

        # ---------------------------------------------------------------
        # Case 2: Customer has MORE tokens than SDN → CLEAR (F+ 1A)
        # ---------------------------------------------------------------
        if customer_count > sdn_count:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_CLEAR_WEIGHT,
                detail=(
                    f"Customer has more name tokens ({customer_count}) than SDN "
                    f"({sdn_count}) — name mismatch [F+ 1A]. "
                    f"Customer={sorted(customer_tokens)} SDN={sorted(sdn_tokens)}"
                ),
            )

        # ---------------------------------------------------------------
        # Case 1: Equal token counts
        # ---------------------------------------------------------------
        if customer_count == sdn_count:
            if customer_tokens == sdn_tokens:
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="ESCALATE",
                    weight=_ESCALATE_WEIGHT,
                    detail=(
                        f"All {customer_count} name tokens match (order-independent) "
                        f"— name match, escalating for further review. "
                        f"Tokens={sorted(customer_tokens)}"
                    ),
                )
            else:
                mismatched = customer_tokens.symmetric_difference(sdn_tokens)
                return RuleFlag(
                    rule_name=self.name,
                    triggered=True,
                    direction="CLEAR",
                    weight=_CLEAR_WEIGHT,
                    detail=(
                        f"Equal token count but tokens differ — name mismatch [F+ 1A]. "
                        f"Differing tokens: {sorted(mismatched)}"
                    ),
                )

        # ---------------------------------------------------------------
        # Case 3: SDN has MORE tokens than customer
        # ---------------------------------------------------------------
        all_customer_in_sdn = customer_tokens.issubset(sdn_tokens)
        if all_customer_in_sdn:
            extra_sdn = sdn_tokens - customer_tokens
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="ESCALATE",
                weight=_ESCALATE_WEIGHT,
                detail=(
                    f"All customer tokens found in SDN name (SDN has extra tokens: "
                    f"{sorted(extra_sdn)}) — name match, escalating for further review"
                ),
            )
        else:
            missing = customer_tokens - sdn_tokens
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=_CLEAR_WEIGHT,
                detail=(
                    f"Customer tokens not found in SDN name — name mismatch [F+ 1A]. "
                    f"Unmatched customer tokens: {sorted(missing)}"
                ),
            )
