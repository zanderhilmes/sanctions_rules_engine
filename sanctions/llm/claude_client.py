"""
Anthropic SDK wrapper for the LLM review layer.

Model selection:
  - Default: claude-haiku-4-5-20251001 (fast, cost-efficient)
  - Escalation: claude-sonnet-4-6 when match_score >= strong_model_score_threshold

Fail-safe: any JSON parse failure → ESCALATE (never auto-clear on ambiguity).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple

import anthropic

from sanctions.models import Alert, Decision, Disposition
from sanctions.llm.prompt_builder import build_prompt, get_system_prompt

log = logging.getLogger(__name__)

_REQUIRED_KEYS = {"decision", "confidence", "rationale", "key_factors"}


class ClaudeClient:
    def __init__(
        self,
        api_key: str,
        model: str = "claude-haiku-4-5-20251001",
        escalation_model: str = "claude-sonnet-4-6",
        strong_model_score_threshold: float = 70.0,
        max_tokens: int = 512,
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.escalation_model = escalation_model
        self.strong_model_score_threshold = strong_model_score_threshold
        self.max_tokens = max_tokens

    def _select_model(self, alert: Alert) -> str:
        if alert.match_score >= self.strong_model_score_threshold:
            log.debug(
                "Using escalation model %s for score %.1f",
                self.escalation_model, alert.match_score,
            )
            return self.escalation_model
        return self.model

    def _call_api(self, model: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=model,
            max_tokens=self.max_tokens,
            system=get_system_prompt(),
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text.strip()

    def _parse_response(self, raw: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from response, handling markdown code fences."""
        text = raw.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first line (```json or ```) and last line (```)
            inner_lines = []
            started = False
            for line in lines:
                if line.startswith("```") and not started:
                    started = True
                    continue
                if line.startswith("```") and started:
                    break
                if started:
                    inner_lines.append(line)
            text = "\n".join(inner_lines)

        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                return None
            if not _REQUIRED_KEYS.issubset(data.keys()):
                log.warning("LLM response missing keys: %s", _REQUIRED_KEYS - data.keys())
                return None
            return data
        except json.JSONDecodeError as exc:
            log.warning("JSON parse error: %s | raw=%r", exc, raw[:200])
            return None

    def review(self, alert: Alert, disposition: Disposition) -> Tuple[Decision, float, str, str]:
        """
        Call the LLM and return (decision, confidence, rationale, model_used).
        On any failure → ESCALATE with explanation.
        """
        model = self._select_model(alert)
        user_prompt = build_prompt(alert, disposition)

        try:
            raw = self._call_api(model, user_prompt)
            log.debug("LLM raw response: %r", raw[:300])
        except anthropic.APIError as exc:
            log.error("Anthropic API error: %s", exc)
            return (
                Decision.ESCALATE,
                1.0,
                f"API error during LLM review: {exc}",
                model,
            )

        parsed = self._parse_response(raw)
        if parsed is None:
            return (
                Decision.ESCALATE,
                1.0,
                f"LLM returned unparseable response — escalating as fail-safe. Raw: {raw[:100]}",
                model,
            )

        raw_decision = str(parsed.get("decision", "")).upper()
        if raw_decision == "AUTO_CLEAR":
            decision = Decision.AUTO_CLEAR
        else:
            decision = Decision.ESCALATE  # Default to escalate for any unexpected value

        try:
            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.5

        rationale = str(parsed.get("rationale", ""))
        key_factors = parsed.get("key_factors", [])
        if isinstance(key_factors, list) and key_factors:
            rationale = rationale + " | Factors: " + "; ".join(str(f) for f in key_factors[:3])

        return decision, confidence, rationale, model
