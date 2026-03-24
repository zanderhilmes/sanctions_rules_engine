"""
OFACEnricher — backfills sdn_dob by looking up the matched entity in the OFAC
sdn_advanced.xml SDN list.

NOTE: Option 1 (preferred) — fix ERF_DOB in Bridger export settings so that the
SDN DOB is populated directly in the Bridger CSV.  Disable this enricher
(ofac.enabled: false in config.yaml) once Bridger populates ERF_DOB.

Option 2 (this implementation) is a temporary measure that downloads the free
OFAC SDN XML at startup and backfills sdn_dob from the parsed index.

XML source: https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml

Schema notes (sdn_advanced.xml — as of 2026):
  Namespace : https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML
  Individuals detected by NamePartTypeID 1520 (Last Name) or 1521 (First Name)
  DOB lives in:
    Profile → Feature[@FeatureTypeID='8'] → FeatureVersion → DatePeriod
              → Start[@Approximate] → From → Year / Month / Day
  Names live in:
    Profile → Identity → Alias → DocumentedName → DocumentedNamePart
              → NamePartValue[@NamePartGroupID]
    NamePartGroupID is resolved to NamePartTypeID via:
    Profile → Identity → NamePartGroups → MasterNamePartGroup
              → NamePartGroup[@ID][@NamePartTypeID]
"""
from __future__ import annotations

import logging
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional

log = logging.getLogger(__name__)

_NS = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"

# NamePartTypeID values for individual name components
_LAST_NAME_TYPE  = "1520"
_FIRST_NAME_TYPE = "1521"
_MIDDLE_NAME_TYPE = "1522"
_INDIVIDUAL_NAME_TYPES = {_LAST_NAME_TYPE, _FIRST_NAME_TYPE, _MIDDLE_NAME_TYPE}

# FeatureTypeID for Birthdate
_BIRTHDATE_FEATURE_TYPE = "8"


def _q(tag: str) -> str:
    return f"{{{_NS}}}{tag}"


def _text(el, tag: str) -> Optional[str]:
    """Return stripped text of a child element, or None."""
    child = el.find(_q(tag))
    return child.text.strip() if child is not None and child.text else None


def _build_dob_from_period(dp_el) -> Optional[str]:
    """
    Extract a DOB string from a DatePeriod element.

    Returns 'YYYY-MM-DD' for exact dates, 'YYYY' for year-only or approximate.
    """
    start = dp_el.find(_q("Start"))
    if start is None:
        return None
    from_el = start.find(_q("From"))
    if from_el is None:
        return None

    year_text = _text(from_el, "Year")
    if not year_text:
        return None
    try:
        year = int(year_text)
    except ValueError:
        return None

    # If approximate or month/day missing, return year only
    approximate = start.get("Approximate", "false").lower() == "true"
    month_text = _text(from_el, "Month")
    day_text = _text(from_el, "Day")

    if not approximate and month_text and day_text:
        try:
            from datetime import date as _date
            return _date(year, int(month_text), int(day_text)).isoformat()
        except ValueError:
            pass

    return str(year)


def _tokenize_name(name: str) -> FrozenSet[str]:
    """Same normalization as NameComponentRule._tokenize — uppercase frozenset."""
    normalized = re.sub(r"[-.,/]", " ", name)
    normalized = re.sub(r"[^\w\s]", "", normalized)
    return frozenset(t.upper() for t in normalized.split() if t)


class OFACEnricher:
    """
    Enriches an Alert with sdn_dob by looking up the matched SDN entity name
    in a locally cached copy of sdn_advanced.xml.

    NOTE: Option 1 (preferred) is to fix ERF_DOB in Bridger export settings.
    Disable via ofac.enabled: false in config.yaml once Bridger populates ERF_DOB.
    """

    def __init__(
        self,
        xml_url: str = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml",
        cache_path: str = "data/sdn_advanced.xml",
        max_age_hours: int = 24,
        timeout_seconds: int = 30,
    ) -> None:
        self._index: Dict[FrozenSet[str], List[str]] = {}
        xml_data = self._get_xml(xml_url, cache_path, max_age_hours, timeout_seconds)
        self._build_index(xml_data)

    def _get_xml(
        self,
        url: str,
        cache_path: str,
        max_age_hours: int,
        timeout_seconds: int,
    ) -> bytes:
        p = Path(cache_path)
        if p.exists():
            age_hours = (time.time() - p.stat().st_mtime) / 3600
            if age_hours < max_age_hours:
                log.info("[ofac] Using cached XML: %s (%.1fh old)", cache_path, age_hours)
                return p.read_bytes()
            log.info("[ofac] Cache expired (%.1fh old) — refreshing from %s", age_hours, url)
        else:
            log.info("[ofac] Downloading OFAC SDN XML from %s", url)

        p.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "sanctions-rules-engine/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            data = resp.read()
        p.write_bytes(data)
        log.info("[ofac] Downloaded and cached %s (%.1f MB)", cache_path, len(data) / 1_048_576)
        return data

    def _build_index(self, xml_data: bytes) -> None:
        """
        Parse sdn_advanced.xml and build a name-token → DOB index.

        Only indexes Individual entries (those with First/Last Name parts).
        Aliases sharing the same entry DOB are indexed under each alias name.
        """
        root = ET.fromstring(xml_data)
        parties_el = root.find(_q("DistinctParties"))
        if parties_el is None:
            log.warning("[ofac] No DistinctParties element found in XML")
            return

        individuals_with_dob = 0

        for party in parties_el:
            profile = party.find(_q("Profile"))
            if profile is None:
                continue

            # ---- Collect DOBs from Birthdate features (FeatureTypeID=8) ----
            dobs: List[str] = []
            for feat in profile.findall(_q("Feature")):
                if feat.get("FeatureTypeID") != _BIRTHDATE_FEATURE_TYPE:
                    continue
                for fv in feat.findall(_q("FeatureVersion")):
                    dp = fv.find(_q("DatePeriod"))
                    if dp is None:
                        continue
                    dob = _build_dob_from_period(dp)
                    if dob:
                        dobs.append(dob)

            if not dobs:
                continue  # No usable DOB — skip entry

            # ---- Build NamePartGroupID → NamePartTypeID map ----
            for identity in profile.findall(_q("Identity")):
                group_type: Dict[str, str] = {}
                npg_container = identity.find(_q("NamePartGroups"))
                if npg_container is not None:
                    for mpg in npg_container.findall(_q("MasterNamePartGroup")):
                        for npg in mpg.findall(_q("NamePartGroup")):
                            gid = npg.get("ID")
                            tid = npg.get("NamePartTypeID")
                            if gid and tid:
                                group_type[gid] = tid

                # Only process identities that have individual-style name parts
                if not any(t in _INDIVIDUAL_NAME_TYPES for t in group_type.values()):
                    continue

                # ---- Index each alias's name tokens → DOBs ----
                for alias in identity.findall(_q("Alias")):
                    for doc_name in alias.findall(_q("DocumentedName")):
                        parts: List[str] = []
                        for dnp in doc_name.findall(_q("DocumentedNamePart")):
                            npv = dnp.find(_q("NamePartValue"))
                            if npv is None or not npv.text:
                                continue
                            gid = npv.get("NamePartGroupID", "")
                            ntype = group_type.get(gid, "")
                            # Only include individual name part types
                            if ntype in _INDIVIDUAL_NAME_TYPES:
                                parts.append(npv.text.strip())

                        if not parts:
                            continue
                        tokens = _tokenize_name(" ".join(parts))
                        if tokens:
                            self._index.setdefault(tokens, []).extend(dobs)

                individuals_with_dob += 1

        log.info(
            "[ofac] Index built: %d individuals with DOB data (%d unique name-token sets)",
            individuals_with_dob, len(self._index),
        )

    def enrich(self, alert) -> None:
        """Backfills alert.sdn_dob from OFAC XML index. Never raises."""
        try:
            self._enrich(alert)
        except Exception as exc:
            log.warning("[ofac] Enrichment error for alert %s: %s", alert.alert_id, exc)

    def _enrich(self, alert) -> None:
        if alert.sdn_dob:
            return  # Already populated (e.g. from Bridger ERF_DOB)
        if not alert.sdn_name:
            return

        tokens = _tokenize_name(alert.sdn_name)
        if not tokens:
            return

        matches = self._index.get(tokens)
        if not matches:
            log.debug("[ofac] No DOB found for SDN '%s'", alert.sdn_name)
            return

        # Deduplicate while preserving insertion order
        unique_dobs = list(dict.fromkeys(matches))

        if len(unique_dobs) == 1:
            alert.sdn_dob = unique_dobs[0]
            log.info(
                "[ofac] Alert %s: backfilled sdn_dob=%s for SDN '%s'",
                alert.alert_id, alert.sdn_dob, alert.sdn_name,
            )
        else:
            log.debug(
                "[ofac] Alert %s: multiple DOBs %s for SDN '%s' — skipping (ambiguous)",
                alert.alert_id, unique_dobs, alert.sdn_name,
            )
