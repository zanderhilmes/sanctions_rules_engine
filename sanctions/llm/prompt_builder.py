"""
Builds structured prompts for the Claude LLM review layer.

Output format enforced: JSON with keys { decision, confidence, rationale, key_factors }
"""
from __future__ import annotations

from typing import List

from sanctions.models import Alert, Disposition, RuleFlag

_SYSTEM_PROMPT = """\
You are a sanctions compliance analyst reviewing potential false-positive alerts \
against the OFAC Specially Designated Nationals (SDN) watchlist.

Your task is to determine whether an alert is a FALSE POSITIVE (safe to auto-clear) \
or requires ESCALATION to a human compliance officer.

CLEARING POLICY — F+ 1B (DOB mismatch):
Per compliance policy, a confirmed date-of-birth mismatch between the customer and the \
SDN entry is independently sufficient to clear an alert (F+ 1Bwc). When the dob_mismatch \
rule has fired with direction=CLEAR, you MUST clear the alert unless a specific reason \
exists to doubt the DOB data (e.g., the DOB source is unreliable or the gap is less than \
2 years). Do NOT require SSN confirmation or third-party lookup (TLOxp/Notary) as a \
precondition for clearing on DOB mismatch grounds.

DECISION TREE (follow in order):
1. If SDN DOB is known and does NOT match customer DOB → AUTO_CLEAR (F+ 1B) unless \
   there is a specific reason to doubt the DOB data.
2. If SDN DOB is unknown → evaluate name, geography, and entity type.
3. If SDN DOB matches customer DOB exactly → ESCALATE or perform alternative reviews.

OTHER GUIDELINES:
- When in doubt on non-DOB grounds, ESCALATE. A genuine SDN match carries severe risk.
- Consider name similarity, geographic plausibility, entity type, and SDN program context.

Respond ONLY with valid JSON matching this exact schema:
{
  "decision": "AUTO_CLEAR" | "ESCALATE",
  "confidence": <float 0.0-1.0>,
  "rationale": "<1-3 sentence explanation>",
  "key_factors": ["<factor 1>", "<factor 2>", ...]
}

Do not include any text outside the JSON object."""


def _format_rule_flags(flags: List[RuleFlag]) -> str:
    if not flags:
        return "  (no rules fired)"
    lines = []
    for f in flags:
        status = f"[{f.direction or 'NO_SIGNAL'}]" if f.triggered else "[not triggered]"
        lines.append(f"  • {f.rule_name} {status}: {f.detail}")
    return "\n".join(lines)


def _format_customer_profile(alert: Alert) -> str:
    """Build the customer profile section from Notary/TLOxp enrichment data."""
    lines = []

    verified_str = "YES (IDV-verified or SSN confirmed)" if alert.customer_verified else "NO (unverified account)"
    lines.append(f"| Account Verified  | {verified_str:<45}|")

    dob_str = alert.customer_dob or "not available"
    dob_source = ""
    if alert.customer_dob:
        if alert.tlo_dob and alert.customer_dob == alert.tlo_dob:
            dob_source = " (via TLOxp)"
        elif alert.notary_hit:
            dob_source = " (via Notary)"
    lines.append(f"| Customer DOB      | {dob_str + dob_source:<45}|")

    email_str = "present" if alert.customer_email else "not on file"
    lines.append(f"| Email on File     | {email_str:<45}|")

    ssn_str = "confirmed on file" if alert.customer_ssn_confirmed else "not confirmed"
    lines.append(f"| SSN               | {ssn_str:<45}|")

    notary_str = {True: "found", False: "not found", None: "not queried"}.get(alert.notary_hit, "not queried")
    tlo_str = {True: "found", False: "not found", None: "not queried"}.get(alert.tlo_hit, "not queried")
    lines.append(f"| Notary lookup     | {notary_str:<45}|")
    lines.append(f"| TLOxp lookup      | {tlo_str:<45}|")

    return "\n".join(lines)


def build_prompt(alert: Alert, disposition: Disposition) -> str:
    """Build the user-turn prompt for the LLM."""
    aliases = ", ".join(alert.sdn_aliases[:5]) if alert.sdn_aliases else "none on record"
    sdn_country = alert.sdn_country or "unknown"
    sdn_type = alert.sdn_type or "unknown"
    sdn_program = alert.sdn_program or "unknown"
    customer_state = alert.customer_state or "unknown"
    zip_display = alert.zip_code or "not provided"

    rule_summary = _format_rule_flags(disposition.rule_flags)
    customer_profile = _format_customer_profile(alert)

    customer_dob_display = alert.customer_dob or "not available"
    sdn_dob_display = alert.sdn_dob or "not available"

    prompt = f"""\
## Alert Under Review

| Field            | Value                          |
|------------------|--------------------------------|
| Customer Name    | {alert.customer_name}          |
| SDN Name         | {alert.sdn_name}               |
| Match Score      | {alert.match_score:.1f} / 100  |
| Customer DOB     | {customer_dob_display}         |
| SDN DOB          | {sdn_dob_display}              |
| Customer Zip     | {zip_display}                  |
| Customer State   | {customer_state}               |
| SDN Type         | {sdn_type}                     |
| SDN Country      | {sdn_country}                  |
| SDN Program      | {sdn_program}                  |
| SDN Aliases      | {aliases}                      |

## Customer Profile (from Notary / TLOxp)

| Field             | Value                                                        |
|-------------------|--------------------------------------------------------------|
{customer_profile}

## Rule Engine Findings

{rule_summary}

Rule engine weighted confidence score: {disposition.confidence:.3f} (threshold: 0.65)

## Reasoning Checklist

Please consider the following in order:
1. **Date of birth (apply first — F+ 1B policy)**:
   - Customer DOB: {customer_dob_display} | SDN DOB: {sdn_dob_display}
   - If both are known and do NOT match → AUTO_CLEAR per policy. Do not require SSN or
     third-party lookup to clear on this basis. Only deviate if the gap is less than 2 years
     or there is a specific reason to doubt the DOB data.
   - If SDN DOB is unknown → skip to step 2.
   - If both match exactly → ESCALATE or apply alternative reviews.
2. **Name similarity**: How closely does the customer name match the SDN name and aliases?
   Are there transliteration differences, honorifics, or name-order variations that explain the match?
3. **Geographic plausibility**: Is it plausible that a {customer_state}-based customer
   is the same person/entity as the {sdn_country} SDN entry?
4. **Account verification**: The customer account is {'VERIFIED' if alert.customer_verified else 'UNVERIFIED'}.
   {'Verified PII should be weighted more heavily.' if alert.customer_verified else 'Lack of verification is not itself a reason to override a DOB mismatch clearing.'}
5. **SDN program context**: The SDN is listed under program '{sdn_program}'.
   Does the customer's profile fit the targeted population?
6. **Entity type**: The SDN is a '{sdn_type}'. Does this match the customer type?
7. **Alias coverage**: Do any SDN aliases provide a closer match to the customer name?

Respond with JSON only."""

    return prompt


def get_system_prompt() -> str:
    return _SYSTEM_PROMPT
