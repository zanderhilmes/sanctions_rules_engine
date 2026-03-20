"""
Abstract base class for all sanctions compliance rules.

To add a new rule:
1. Create a new file in sanctions/rules/ (e.g. rule_name_tokens.py)
2. Subclass BaseRule
3. Set class-level `name`, `weight`, and optionally `priority`
4. Implement evaluate(alert) -> RuleFlag
5. Register in main.py or rules/__init__.py
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from sanctions.models import Alert, RuleFlag


class BaseRule(ABC):
    """Abstract rule.  Subclasses must define name, weight, and evaluate()."""

    #: Unique identifier used in audit output
    name: str = "unnamed_rule"

    #: Contribution to the weighted-vote accumulator (0.0–1.0)
    weight: float = 0.0

    #: Lower number = evaluated first; useful when one rule can short-circuit
    priority: int = 100

    @abstractmethod
    def evaluate(self, alert: Alert) -> RuleFlag:
        """
        Evaluate the alert against this rule.

        Returns a RuleFlag with:
            triggered  True if rule fired
            direction  "CLEAR" | "ESCALATE" | None
            detail     Human-readable explanation for audit trail
        """
        ...
