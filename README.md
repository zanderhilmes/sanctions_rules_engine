# Sanctions Rules Engine

A Python rules engine for auto-clearing and escalating OFAC sanctions screening alerts from Bridger. It applies a deterministic rule hierarchy first, then falls back to an LLM (Claude) for ambiguous cases.

## Overview

Bridger produces a screening alert for every customer name that fuzzy-matches the OFAC SDN list. Most alerts are false positives. This engine processes those alerts and automatically clears the obvious false positives, escalates true matches, and sends borderline cases to Claude for a reasoned determination.

**Decision outcomes:**

| Decision | Meaning |
|---|---|
| `AUTO_CLEAR` | Deterministically cleared by rules — no manual review needed |
| `ESCALATE` | High confidence of a true match — send to a human analyst |
| `PENDING` | Inconclusive — sent to Claude LLM for a reasoned determination |

---

## Architecture

```
Bridger CSV
    │
    ▼
SanctionsPipeline
    │
    ├── SnowflakeEnricher   (customer DOB, IDV status, account creation date)
    ├── OFACEnricher        (SDN DOB + date-added from sdn_advanced.xml)
    └── TLOxpEnricher       (customer DOB + state from LexisNexis — stub)
    │
    ├── RuleRegistry        (weighted-vote engine, runs all rules)
    │
    └── ClaudeClient        (LLM review for PENDING cases only)
    │
    ▼
audit_trail.csv / audit_trail.json
```

### Key files

| Path | Purpose |
|---|---|
| `main.py` | CLI entrypoint |
| `config.yaml` | All configuration (models, thresholds, credentials) |
| `sanctions/models.py` | Pydantic data models: `Alert`, `RuleFlag`, `Disposition`, `AuditRecord` |
| `sanctions/config.py` | Typed config loader with env-var interpolation |
| `sanctions/pipeline/processor.py` | `SanctionsPipeline` orchestrator |
| `sanctions/rules/registry.py` | Weighted-vote accumulator + resolution logic |
| `sanctions/enrichment/` | Snowflake, OFAC XML, TLOxp enrichers |
| `sanctions/rules/` | Individual rule implementations |
| `sanctions/llm/` | Claude API client + prompt builder |

---

## Rules

All rules run on every alert for audit completeness. The registry applies this resolution order after all rules have fired:

1. **HARD CLEAR** — any CLEAR vote with weight ≥ 0.90 → `AUTO_CLEAR` (overrides name-match escalation)
2. **HARD ESCALATE** — any ESCALATE vote with weight ≥ 0.90 → `ESCALATE`
3. **Weighted clear score** ≥ threshold (default 0.65) → `AUTO_CLEAR`
4. Otherwise → `PENDING` (sent to LLM)

| Rule | Priority | Direction | Weight | Guide ref | Trigger condition |
|---|---|---|---|---|---|
| `name_components` | 5 | CLEAR / ESCALATE | 0.85 / 0.80 | F+ 1A | Token-set comparison (3-case table) |
| `alias_match` | 6 | ESCALATE | 0.95 | — | Customer name matches an SDN alias |
| `dob_mismatch` | 15 | CLEAR | 0.90 | F+ 1B | Customer DOB ≠ SDN DOB (±1yr tolerance for year-only) |
| `age_improbability` | 16 | CLEAR | 0.90 / 0.50 | F+ 1D | SDN added before customer was born (hard) or customer was very young (soft) |
| `low_score` | 20 | CLEAR | 0.60 | — | Match score < 30 |
| `common_name` | 30 | CLEAR | 0.45 | — | Customer name is a high-frequency common name |
| `geography` | 40 | CLEAR | 0.35 | — | US customer vs foreign SDN (state ≠ SDN country) |

**Key hierarchy note:** A name token match (`name_components` → HARD ESCALATE) is overridden by a DOB mismatch (`dob_mismatch` → HARD CLEAR). This implements the guide's instruction to proceed from name evaluation to DOB evaluation — a confirmed DOB mismatch clears the alert even if the name is an exact match.

---

## Enrichment

Customer DOB is the most powerful signal (enables DOB mismatch hard-clear). The pipeline backfills it from multiple sources in order of preference:

### Customer DOB sources (first hit wins)

1. **`IDENTITY_DOB_HISTORY`** — primary source; the table that backs `CASH_W_DOB`. Has a full `DOB DATE` column.
2. **`IDENTITY_IDV_ATTEMPTS`** — fallback; only present for customers who completed IDV.
3. **TLOxp (LexisNexis)** — stub; activated once credentials are provisioned.
4. **Account creation date proxy** — when no DOB is available, `AgeImprobabilityRule` derives the latest possible birth year from `CUSTOMER_CREATED_AT` minus the minimum signup age (18). Only fires the age rule; does not populate `customer_dob`.

### SDN DOB + date-added

OFAC's `sdn_advanced.xml` is downloaded at startup (cached 24h) and used to backfill:
- `sdn_dob` — the SDN entity's birth date (required for DOB mismatch rule)
- `sdn_date_added` — the date the entity was listed (required for age improbability rule)

Both fields are typically absent from Bridger CSV exports. The preferred long-term fix is to configure Bridger's `ERF_DOB` export field; until then, the OFAC XML enricher handles it automatically.

---

## Quickstart

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

```bash
cp .env.example .env
# Add ANTHROPIC_API_KEY (required for LLM review of PENDING cases)
```

### 3. Configure Snowflake (optional — rules run without it)

Edit `config.yaml`:

```yaml
snowflake:
  enabled: true
  account: "${SNOWFLAKE_ACCOUNT}"    # set in .env or environment
  user: "${SNOWFLAKE_USER}"
  warehouse: "ADHOC__MEDIUM"
  authenticator: "externalbrowser"   # or "https://login.block.xyz" for Okta SSO
```

### 4. Generate sample data and run

```bash
# Generate 50 synthetic alerts for testing
python main.py --generate-sample

# Run the pipeline
python main.py --input data/sample_alerts.csv

# Run on a real Bridger CSV
python main.py --input path/to/bridger_export.csv

# Debug logging
python main.py --input data/sample_alerts.csv -v
```

### 5. Review output

Results are written to:
- `output/audit_trail.csv` — one row per alert with decision, confidence, triggered rules
- `output/audit_trail.json` — same in JSON-lines format

---

## Configuration reference

```yaml
llm:
  model: "claude-haiku-4-5-20251001"       # Fast model for most LLM calls
  escalation_model: "claude-sonnet-4-6"    # Stronger model when match_score >= threshold
  strong_model_score_threshold: 70.0       # Score above which to use the stronger model
  max_tokens: 512

rules:
  auto_clear_confidence_threshold: 0.65    # Weighted clear score to auto-clear
  escalate_hard_weight: 0.90               # ESCALATE weight for hard-escalate
  clear_hard_weight: 0.90                  # CLEAR weight for hard-clear
  low_score_clear_threshold: 30.0          # Score below which low_score rule fires
  common_names_file: "data/common_names.txt"
  age_improbability_max_years: 5           # Age (years) below which soft-clear fires
  min_signup_age: 18                       # Minimum age at account creation (DOB proxy)

snowflake:
  enabled: true
  dob_history_table: "APP_CASH.HEALTH.IDENTITY_DOB_HISTORY"
  account_table: "APP_CASH.APP.CASH_CUSTOMER_IDENTITY_W_AFTERPAY"
  account_id_col: "CUSTOMER_TOKEN"
  account_created_col: "CUSTOMER_CREATED_AT"

ofac:
  enabled: true
  cache_path: "data/sdn_advanced.xml"
  max_age_hours: 24

tlo:
  enabled: false          # Enable once TLOXP_API_KEY + TLOXP_API_URL are provisioned
```

---

## Adding a custom rule

1. Create `sanctions/rules/rule_my_rule.py`:

```python
from sanctions.models import Alert, RuleFlag
from sanctions.rules.base_rule import BaseRule

class MyRule(BaseRule):
    name = "my_rule"
    weight = 0.50
    priority = 50   # Higher number = runs later

    def evaluate(self, alert: Alert) -> RuleFlag:
        if <condition>:
            return RuleFlag(
                rule_name=self.name,
                triggered=True,
                direction="CLEAR",   # or "ESCALATE"
                weight=self.weight,
                detail="Reason for this decision",
            )
        return RuleFlag(rule_name=self.name, triggered=False, direction=None, weight=self.weight)
```

2. Register it in `sanctions/pipeline/processor.py`:

```python
from sanctions.rules.rule_my_rule import MyRule
# ...
self.registry.register(MyRule())
```

---

## TLOxp setup (LexisNexis)

Once credentials are provisioned:

1. Set `TLOXP_API_KEY` and `TLOXP_API_URL` in `.env`
2. Fill in the two TODOs in `sanctions/enrichment/tlo_client.py`:
   - `_SEARCH_ENDPOINT` — the actual search path
   - `_parse_response()` — field names in the response JSON
3. Set `tlo.enabled: true` in `config.yaml`
