"""
CountryMismatchRule — hard-clears alerts where the customer has a confirmed US address
from an IDV table and the SDN entity's listed location is non-US.

STATUS: DISABLED — registered in processor.py only once both data sources are available.

Required data sources (neither is currently populated in the live pipeline):

  1. CUSTOMER — confirmed US address from IDV tables (Snowflake):
       alert.customer_state populated by SnowflakeEnricher._lookup_customer_state()
       Configure: snowflake.address_state_col in config.yaml (e.g. "STATE")
       This confirms the customer physically verified a US address through KYC/IDV —
       NOT derived from zip code and NOT inferred from SSN presence.

  2. SDN — reliable non-POB location signal:
       alert.sdn_country must NOT be sourced from Place of Birth (OFAC FeatureTypeID=9)
       or nationality.  An SDN born in Mexico could reside anywhere; POB ≠ current
       location and should not drive clearing decisions.
       TODO: identify a suitable SDN location source (e.g. OFAC address features,
       a separate watchlist feed, or SDN program-based regional inference) and wire
       it into a new enricher or a separate Alert field (sdn_location / sdn_address_country)
       distinct from sdn_country.

NOTE on sdn_country:
  The OFACEnricher continues to populate sdn_country from Place of Birth for audit
  trail visibility — it is useful context for human reviewers.  However, it must NOT
  be used as the SDN-side signal for this rule.

Weight / confidence tiers (when rule is re-enabled):

  Tier 1 — IDV-confirmed US state + reliable non-US SDN location:
    → HARD CLEAR (weight=0.95)
    Two independent signals (geography + identity verification) make a true match
    extremely unlikely, warranting higher confidence than DOB mismatch alone (0.90).

Priority 18: after dob_mismatch (15), age_improbability (16), missing_dob (17).
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

_US_IDENTIFIERS = {"US", "USA", "UNITED STATES", "UNITED STATES OF AMERICA", "U.S.", "U.S.A."}

_HARD_CLEAR_WEIGHT = 0.95


def _is_us_country(country: str) -> bool:
    return country.upper().strip() in _US_IDENTIFIERS


class CountryMismatchRule(BaseRule):
    name = "country_mismatch"
    weight = _HARD_CLEAR_WEIGHT
    priority = 18

    def evaluate(self, alert: Alert) -> RuleFlag:
        # ---- Customer side: require IDV-confirmed US address ----
        # customer_state is only populated by SnowflakeEnricher when address_state_col
        # is configured AND a successful IDV attempt with a state value exists.
        # zip_to_state() fallback is explicitly not used here — zip is not IDV-confirmed.
        has_confirmed_us_state = bool(
            alert.customer_state and str(alert.customer_state).strip()
        )
        if not has_confirmed_us_state:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=(
                    "No IDV-confirmed customer state — country mismatch check skipped "
                    "(configure snowflake.address_state_col to enable)"
                ),
            )

        # ---- SDN side: require a reliable non-POB location signal ----
        # TODO: replace with a dedicated sdn_location field sourced from something
        # other than Place of Birth (OFAC FeatureTypeID=9) once that source is
        # identified. For now, the rule cannot fire even when customer_state is set.
        sdn_location = None  # placeholder — see module docstring

        if not sdn_location:
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=(
                    "No reliable SDN location signal available — country mismatch check "
                    "skipped (POB/nationality not used; see rule TODO)"
                ),
            )

        if _is_us_country(sdn_location):
            return RuleFlag(
                rule_name=self.name,
                triggered=False,
                direction=None,
                weight=self.weight,
                detail=f"SDN location is US ('{sdn_location}') — no geographic mismatch",
            )

        return RuleFlag(
            rule_name=self.name,
            triggered=True,
            direction="CLEAR",
            weight=_HARD_CLEAR_WEIGHT,
            detail=(
                f"Country mismatch: customer has IDV-confirmed US address "
                f"({alert.customer_state}) but SDN location is '{sdn_location}' — "
                f"two independent signals (verified geography + identity) strongly "
                f"indicate false positive [F+ country mismatch]"
            ),
        )
