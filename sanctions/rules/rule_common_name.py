"""
CommonNameRule — clears alerts where the customer name appears in a
maintained list of high-population common names.

Rationale: names like "John Smith" or "Maria Garcia" have extremely high
base-rate frequency in the general population, making a coincidental match
with an SDN entry much more likely than a genuine hit.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Set

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

log = logging.getLogger(__name__)


def _load_common_names(path: str) -> Set[str]:
    p = Path(path)
    if not p.exists():
        log.warning("Common names file not found: %s", path)
        return set()
    names: Set[str] = set()
    with open(p, encoding="utf-8") as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith("#"):
                names.add(name.upper())
    log.info("Loaded %d common names from %s", len(names), path)
    return names


class CommonNameRule(BaseRule):
    name = "common_name"
    weight = 0.45
    priority = 20

    def __init__(self, common_names_file: str = "data/common_names.txt") -> None:
        self._names: Set[str] = _load_common_names(common_names_file)

    def evaluate(self, alert: Alert) -> RuleFlag:
        if not self._names:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="Common names list not loaded; rule skipped",
            )

        customer_upper = alert.customer_name.upper().strip()
        if customer_upper in self._names:
            # Annotate the escalation path per guide decision table:
            #   verified account            → L2 escalation
            #   unverified + email present  → L2 escalation
            #   unverified + no email       → denylist path (no L2 required)
            if alert.customer_verified:
                path_note = "verified account — escalate to L2 if not otherwise cleared"
            elif alert.customer_email:
                path_note = "unverified account with email — escalate to L2 if not otherwise cleared"
            else:
                path_note = "unverified account with no email — denylist path per guide (no L2 required)"

            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=self.weight,
                detail=(
                    f"'{alert.customer_name}' is a high-frequency common name "
                    f"with elevated false-positive base rate. {path_note}"
                ),
            )

        # Also check if the SDN name itself is a common name (different direction —
        # a common SDN name means many innocent people will match)
        sdn_upper = alert.sdn_name.upper().strip()
        if sdn_upper in self._names:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=self.weight * 0.75,  # Slightly lower confidence
                detail=(
                    f"SDN name '{alert.sdn_name}' is a high-frequency common name; "
                    f"match is likely coincidental"
                ),
            )

        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=f"'{alert.customer_name}' not found in common names list",
        )
