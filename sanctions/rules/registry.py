"""
Rule registry: weighted-vote accumulator with hard-clear and hard-escalate signals.

Vote accumulation logic:
  - Each rule returns a RuleFlag with direction CLEAR / ESCALATE / None
  - effective_weight = flag.weight (allows a rule to return different weights per direction)
  - CLEAR votes add to clear_score; soft ESCALATE votes subtract from clear_score
  - If clear_score >= auto_clear_confidence_threshold → AUTO_CLEAR
  - If any CLEAR vote has effective_weight >= clear_hard_weight → HARD CLEAR
  - If any ESCALATE vote has effective_weight >= escalate_hard_weight → HARD ESCALATE

Resolution priority (all rules still run for audit completeness):
  1. HARD CLEAR (weight >= 0.90)  — age improbability, low-score DOB mismatch
  2. CONTESTED  — hard ESCALATE present AND a strong-but-not-hard CLEAR vote
                  (weight in [contested_clear_threshold, clear_hard_weight))
                  → PENDING so the LLM can adjudicate the conflict
  3. HARD ESCALATE alone → ESCALATE
  4. Weighted clear_score >= threshold → AUTO_CLEAR
  5. Otherwise → PENDING (sent to LLM)

The contested state (step 2) is what routes high-score DOB-mismatch alerts to the
LLM: name_components fires HARD ESCALATE (0.95) and dob_mismatch at high match score
fires a contested CLEAR (0.75), triggering LLM review rather than auto-clearing.

Soft ESCALATE votes (weight < escalate_hard_weight) subtract from clear_score rather
than being ignored — this lets risk signals like missing_dob reduce auto-clear confidence
without forcing a hard escalation.
"""
from __future__ import annotations

import logging
from typing import List

from sanctions.models import Alert, Decision, Disposition, RuleFlag
from sanctions.rules.base_rule import BaseRule

log = logging.getLogger(__name__)


class RuleRegistry:
    def __init__(
        self,
        auto_clear_confidence_threshold: float = 0.65,
        escalate_hard_weight: float = 0.90,
        clear_hard_weight: float = 0.90,
        contested_clear_threshold: float = 0.70,
    ) -> None:
        self._rules: List[BaseRule] = []
        self.auto_clear_threshold = auto_clear_confidence_threshold
        self.escalate_hard_weight = escalate_hard_weight
        self.clear_hard_weight = clear_hard_weight
        self.contested_clear_threshold = contested_clear_threshold

    def register(self, rule: BaseRule) -> None:
        self._rules.append(rule)
        # Keep sorted by priority (ascending = higher priority first)
        self._rules.sort(key=lambda r: r.priority)
        log.debug("Registered rule '%s' (weight=%.2f, priority=%d)",
                  rule.name, rule.weight, rule.priority)

    def evaluate(self, alert: Alert) -> Disposition:
        """Run all rules and return a Disposition."""
        flags: List[RuleFlag] = []
        clear_score = 0.0
        hard_escalate = False
        hard_clear = False
        max_triggered_clear_weight = 0.0

        for rule in self._rules:
            try:
                flag = rule.evaluate(alert)
            except Exception as exc:
                log.error("Rule '%s' raised an exception: %s", rule.name, exc)
                flag = RuleFlag(
                    rule_name=rule.name,
                    triggered=False,
                    direction=None,
                    weight=rule.weight,
                    detail=f"Rule error: {exc}",
                )
            flags.append(flag)

            if flag.triggered:
                # flag.weight carries the effective weight for this specific firing;
                # fall back to class-level rule.weight if not set.
                effective_weight = flag.weight if flag.weight > 0 else rule.weight
                if flag.direction == "CLEAR":
                    clear_score += effective_weight
                    if effective_weight > max_triggered_clear_weight:
                        max_triggered_clear_weight = effective_weight
                    log.debug("Rule '%s' CLEAR vote (running score=%.3f)",
                              rule.name, clear_score)
                    if effective_weight >= self.clear_hard_weight:
                        hard_clear = True
                        log.debug("Rule '%s' HARD CLEAR (weight=%.2f >= %.2f)",
                                  rule.name, effective_weight, self.clear_hard_weight)
                elif flag.direction == "ESCALATE":
                    if effective_weight >= self.escalate_hard_weight:
                        hard_escalate = True
                        log.debug("Rule '%s' HARD ESCALATE (weight=%.2f >= %.2f)",
                                  rule.name, effective_weight, self.escalate_hard_weight)
                    else:
                        # Soft escalate — subtract from clear_score to reduce auto-clear confidence
                        clear_score -= effective_weight
                        log.debug("Rule '%s' soft ESCALATE vote (running score=%.3f)",
                                  rule.name, clear_score)

        # Resolution priority:
        # 1. HARD CLEAR — age improbability, low-score DOB mismatch
        if hard_clear:
            return Disposition(
                decision=Decision.AUTO_CLEAR,
                confidence=1.0,
                rule_flags=flags,
            )

        # 2. CONTESTED — hard escalate + strong-but-not-hard clear → LLM adjudicates
        if hard_escalate and max_triggered_clear_weight >= self.contested_clear_threshold:
            log.debug(
                "Contested: hard ESCALATE + clear weight=%.2f >= threshold=%.2f → PENDING",
                max_triggered_clear_weight, self.contested_clear_threshold,
            )
            return Disposition(
                decision=Decision.PENDING,
                confidence=clear_score,
                rule_flags=flags,
            )

        # 3. HARD ESCALATE alone
        if hard_escalate:
            return Disposition(
                decision=Decision.ESCALATE,
                confidence=1.0,
                rule_flags=flags,
            )

        if clear_score >= self.auto_clear_threshold:
            return Disposition(
                decision=Decision.AUTO_CLEAR,
                confidence=min(clear_score, 1.0),
                rule_flags=flags,
            )

        return Disposition(
            decision=Decision.PENDING,
            confidence=clear_score,
            rule_flags=flags,
        )
