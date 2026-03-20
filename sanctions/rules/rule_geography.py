"""
GeographyRule — uses customer zip code vs. SDN country to assess geographic plausibility.

Logic:
  - US customer (has zip) + SDN entity is non-US country → CLEAR (weight 0.35)
    Rationale: sanctioned foreign nationals/entities typically operate in their home country;
    a US domestic customer with a foreign SDN is an unlikely match.
  - US customer + SDN entity is explicitly US → mild ESCALATE (weight 0.35)
    Rationale: US-based SDN entities are rarer but do exist (domestic crime, etc.)
  - No zip or no SDN country → no signal (direction None)

Non-US SDN country codes indicating clear geographic mismatch with US customer:
All non-"US" / non-"UNITED STATES" country indicators.
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

_US_IDENTIFIERS = {"US", "USA", "UNITED STATES", "UNITED STATES OF AMERICA", "U.S.", "U.S.A."}


def _is_us_country(country: str) -> bool:
    return country.upper().strip() in _US_IDENTIFIERS


class GeographyRule(BaseRule):
    name = "geography"
    weight = 0.35
    priority = 30

    def evaluate(self, alert: Alert) -> RuleFlag:
        has_zip = bool(alert.zip_code and str(alert.zip_code).strip())
        has_state = bool(alert.customer_state)
        has_sdn_country = bool(alert.sdn_country and str(alert.sdn_country).strip())

        if not (has_zip or has_state):
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="No customer zip/state available; geography rule skipped",
            )

        if not has_sdn_country:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail="SDN country unknown; geography rule cannot assess mismatch",
            )

        sdn_is_us = _is_us_country(alert.sdn_country)

        if not sdn_is_us:
            # Customer has US zip, SDN entity is foreign → strong false-positive signal
            state_desc = alert.customer_state or f"zip {alert.zip_code}"
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=self.weight,
                detail=(
                    f"Customer is US-based ({state_desc}) but SDN country is "
                    f"'{alert.sdn_country}' — geographic mismatch favors false positive"
                ),
            )

        # SDN is US-based — mild escalation signal
        state_desc = alert.customer_state or f"zip {alert.zip_code}"
        return RuleFlag(
            rule_name=self.name,
            triggered=True,
            direction="ESCALATE",
            weight=self.weight,  # weight 0.35 < escalate_hard_weight 0.90 → soft escalate only
            detail=(
                f"Both customer ({state_desc}) and SDN entity are US-based — "
                f"geographic overlap is a mild escalation signal"
            ),
        )
