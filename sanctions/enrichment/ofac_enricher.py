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
# 91708 = Paternal Surname / 91709 = Maternal Surname (used in Hispanic naming conventions)
_INDIVIDUAL_NAME_TYPES = {_LAST_NAME_TYPE, _FIRST_NAME_TYPE, _MIDDLE_NAME_TYPE, "91708", "91709"}

# FeatureTypeID for Birthdate and Place of Birth
_BIRTHDATE_FEATURE_TYPE = "8"
_PLACE_OF_BIRTH_FEATURE_TYPE = "9"


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


def _country_from_pob(pob_text: str) -> Optional[str]:
    """
    Extract a country name from a free-text Place of Birth string.

    OFAC POB strings range from simple ('Mexico') to compound
    ('Najf Al Ashraf (Najaf), Iraq', 'Giza, Egypt').  The country is
    consistently the last comma-separated token.

    Returns None for empty, obviously non-country values, or
    strings that are clearly sub-national (e.g. a single US state).
    """
    if not pob_text:
        return None
    # Take the last comma-separated segment and strip trailing parentheticals
    country = pob_text.split(",")[-1].strip()
    country = re.sub(r"\s*\([^)]*\)\s*$", "", country).strip()
    if not country or len(country) < 2:
        return None
    return country


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
        # profile_id → "YYYY-MM-DD" entry date (for sdn_date_added backfill)
        self._date_added: Dict[str, str] = {}
        # name tokens → profile_ids (used to resolve date_added via name lookup)
        self._name_to_profile: Dict[FrozenSet[str], List[str]] = {}
        # name tokens → country of birth (for sdn_country backfill)
        self._pob_index: Dict[FrozenSet[str], List[str]] = {}
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
        Parse sdn_advanced.xml and build:
          _index           : name tokens → DOB list  (for sdn_dob backfill)
          _name_to_profile : name tokens → profile IDs
          _date_added      : profile ID  → entry date (for sdn_date_added backfill)

        Only indexes Individual entries (those with First/Last Name parts).
        """
        root = ET.fromstring(xml_data)

        # ---- Build profile_id → entry date from SanctionsEntries ----
        entries_el = root.find(_q("SanctionsEntries"))
        if entries_el is not None:
            for entry in entries_el:
                profile_id = entry.get("ProfileID")
                if not profile_id:
                    continue
                ee = entry.find(_q("EntryEvent"))
                if ee is None:
                    continue
                date_el = ee.find(_q("Date"))
                if date_el is None:
                    continue
                year = _text(date_el, "Year")
                month = _text(date_el, "Month")
                day = _text(date_el, "Day")
                if year:
                    try:
                        if month and day:
                            from datetime import date as _date
                            d = _date(int(year), int(month), int(day))
                            self._date_added[profile_id] = d.isoformat()
                        else:
                            self._date_added[profile_id] = year
                    except ValueError:
                        self._date_added[profile_id] = year

        parties_el = root.find(_q("DistinctParties"))
        if parties_el is None:
            log.warning("[ofac] No DistinctParties element found in XML")
            return

        individuals_with_dob = 0

        for party in parties_el:
            profile = party.find(_q("Profile"))
            if profile is None:
                continue

            # ---- Collect DOBs and Place of Birth from features ----
            dobs: List[str] = []
            pob_countries: List[str] = []
            for feat in profile.findall(_q("Feature")):
                ftype = feat.get("FeatureTypeID")
                if ftype == _BIRTHDATE_FEATURE_TYPE:
                    for fv in feat.findall(_q("FeatureVersion")):
                        dp = fv.find(_q("DatePeriod"))
                        if dp is None:
                            continue
                        dob = _build_dob_from_period(dp)
                        if dob:
                            dobs.append(dob)
                elif ftype == _PLACE_OF_BIRTH_FEATURE_TYPE:
                    for fv in feat.findall(_q("FeatureVersion")):
                        vd = fv.find(_q("VersionDetail"))
                        if vd is not None and vd.text:
                            country = _country_from_pob(vd.text.strip())
                            if country:
                                pob_countries.append(country)

            if not dobs and not pob_countries:
                continue  # No usable identity data — skip entry

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

                profile_id = profile.get("ID", "")

                # ---- Index each alias's name tokens → DOBs and profile IDs ----
                for alias in identity.findall(_q("Alias")):
                    for doc_name in alias.findall(_q("DocumentedName")):
                        parts: List[str] = []
                        for dnp in doc_name.findall(_q("DocumentedNamePart")):
                            npv = dnp.find(_q("NamePartValue"))
                            if npv is None or not npv.text:
                                continue
                            gid = npv.get("NamePartGroupID", "")
                            ntype = group_type.get(gid, "")
                            if ntype in _INDIVIDUAL_NAME_TYPES:
                                parts.append(npv.text.strip())

                        if not parts:
                            continue
                        tokens = _tokenize_name(" ".join(parts))
                        if tokens:
                            if dobs:
                                self._index.setdefault(tokens, []).extend(dobs)
                            if pob_countries:
                                self._pob_index.setdefault(tokens, []).extend(pob_countries)
                            if profile_id:
                                self._name_to_profile.setdefault(tokens, []).append(profile_id)

                individuals_with_dob += 1

        individuals_with_pob = sum(1 for v in self._pob_index.values() if v)
        log.info(
            "[ofac] Index built: %d individuals with DOB data, %d with country/POB"
            " (%d unique name-token sets)",
            individuals_with_dob, individuals_with_pob, len(self._index),
        )

    def enrich(self, alert) -> None:
        """Backfills alert.sdn_dob from OFAC XML index. Never raises."""
        try:
            self._enrich(alert)
        except Exception as exc:
            log.warning("[ofac] Enrichment error for alert %s: %s", alert.alert_id, exc)

    # Minimum fraction of alert SDN name tokens that must appear in an OFAC
    # index entry's token set to be considered a match.
    _MATCH_THRESHOLD = 0.92

    def _enrich(self, alert) -> None:
        if not alert.sdn_name:
            return

        tokens = _tokenize_name(alert.sdn_name)
        if not tokens:
            return

        # ---- Threshold matching: scan index for entries where ≥92% of the
        #      alert SDN name tokens appear in the OFAC entry's token set.
        #      This handles cases where the Bridger SDN name is a shorter form
        #      of the canonical OFAC name (e.g. "Gerardo Ibarra" matches
        #      "Gerardo RIVERA IBARRA" because both GERARDO and IBARRA are
        #      present in the OFAC entry). ----
        matched_dobs: List[str] = []
        matched_profile_ids: List[str] = []
        matched_countries: List[str] = []

        # Scan DOB index (superset of POB index — any entry with DOB or country)
        all_token_sets = set(self._index.keys()) | set(self._pob_index.keys())
        for index_tokens in all_token_sets:
            overlap = len(tokens & index_tokens) / len(tokens)
            if overlap >= self._MATCH_THRESHOLD:
                matched_dobs.extend(self._index.get(index_tokens, []))
                matched_countries.extend(self._pob_index.get(index_tokens, []))
                matched_profile_ids.extend(
                    self._name_to_profile.get(index_tokens, [])
                )

        # ---- Backfill sdn_dob ----
        if not alert.sdn_dob:
            if matched_dobs:
                unique_dobs = list(dict.fromkeys(matched_dobs))
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
            else:
                log.debug("[ofac] No DOB found for SDN '%s'", alert.sdn_name)

        # ---- Backfill sdn_date_added ----
        if not alert.sdn_date_added:
            if matched_profile_ids:
                unique_ids = list(dict.fromkeys(matched_profile_ids))
                if len(unique_ids) == 1:
                    date_added = self._date_added.get(unique_ids[0])
                    if date_added:
                        alert.sdn_date_added = date_added
                        log.info(
                            "[ofac] Alert %s: backfilled sdn_date_added=%s for SDN '%s'",
                            alert.alert_id, date_added, alert.sdn_name,
                        )

        # ---- Backfill sdn_country (from Place of Birth) ----
        if not alert.sdn_country and matched_countries:
            unique_countries = list(dict.fromkeys(matched_countries))
            if len(unique_countries) == 1:
                alert.sdn_country = unique_countries[0]
                log.info(
                    "[ofac] Alert %s: backfilled sdn_country=%r for SDN '%s' (from POB)",
                    alert.alert_id, alert.sdn_country, alert.sdn_name,
                )
            else:
                log.debug(
                    "[ofac] Alert %s: multiple POB countries %s for SDN '%s' — skipping",
                    alert.alert_id, unique_countries, alert.sdn_name,
                )
