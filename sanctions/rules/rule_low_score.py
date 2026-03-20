"""
LowScoreRule — clears alerts where the match score is below a threshold.

Rationale: screening systems typically assign scores 0–100; a score below 30
indicates a weak string-similarity match and is very unlikely to be a genuine hit.
"""
from __future__ import annotations

from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule


class LowScoreRule(BaseRule):
    name = "low_score"
    weight = 0.60
    priority = 10  # Evaluated early; very high-signal rule

    def __init__(self, threshold: float = 30.0) -> None:
        self.threshold = threshold

    def evaluate(self, alert: Alert) -> RuleFlag:
        if alert.match_score < self.threshold:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",
                weight=self.weight,
                detail=(
                    f"Match score {alert.match_score:.1f} is below "
                    f"auto-clear threshold {self.threshold:.1f}"
                ),
            )
        return RuleFlag(
            rule_name=self.name,
            triggered=False,
            direction=None,
            weight=self.weight,
            detail=f"Match score {alert.match_score:.1f} >= threshold {self.threshold:.1f}",
        )
