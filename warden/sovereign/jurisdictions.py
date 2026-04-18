"""
warden/sovereign/jurisdictions.py
────────────────────────────────────
Jurisdiction definitions and compliance framework registry.

Each jurisdiction describes:
  - Legal territory (code, name, flag)
  - Applicable data-protection frameworks (GDPR, HIPAA, PIPEDA…)
  - Cloud regions within that territory
  - Whether explicit data-residency attestation is required by law
  - AI-specific regulations (EU AI Act, NIST AI RMF, etc.)
  - MASQUE proxy endpoint pool (one per region)

Used by the routing engine and policy validator to enforce data-residency
and generate compliance attestations.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Jurisdiction:
    code:                    str          # "EU", "US", "UK", "CA", "APAC_SG", "AU"
    name:                    str          # "European Union"
    flag:                    str          # emoji flag
    frameworks:              tuple[str, ...]  # applicable compliance frameworks
    ai_regulations:          tuple[str, ...]  # AI-specific rules
    cloud_regions:           tuple[str, ...]  # canonical cloud region IDs
    residency_required:      bool         # law mandates data stay in territory
    cross_border_restricted: bool         # strict cross-border transfer rules
    adequacy_partners:       tuple[str, ...]  # jurisdictions with adequacy decisions


# ── Jurisdiction registry ─────────────────────────────────────────────────────

JURISDICTIONS: dict[str, Jurisdiction] = {

    "EU": Jurisdiction(
        code                   = "EU",
        name                   = "European Union",
        flag                   = "🇪🇺",
        frameworks             = ("GDPR", "NIS2", "DORA", "eIDAS"),
        ai_regulations         = ("EU_AI_ACT", "GPAI_CODE_OF_PRACTICE"),
        cloud_regions          = ("eu-west-1", "eu-west-3", "eu-central-1",
                                  "eu-north-1", "eu-south-1"),
        residency_required     = True,
        cross_border_restricted= True,
        adequacy_partners      = ("UK", "CA", "CH", "IL", "JP", "NZ"),
    ),

    "US": Jurisdiction(
        code                   = "US",
        name                   = "United States",
        flag                   = "🇺🇸",
        frameworks             = ("HIPAA", "SOC2", "FedRAMP", "CCPA", "NIST_CSF"),
        ai_regulations         = ("NIST_AI_RMF", "EO14110", "CISA_AI_ROADMAP"),
        cloud_regions          = ("us-east-1", "us-east-2", "us-west-1",
                                  "us-west-2", "us-gov-east-1"),
        residency_required     = False,
        cross_border_restricted= False,
        adequacy_partners      = ("EU", "UK", "CA", "AU", "JP"),
    ),

    "UK": Jurisdiction(
        code                   = "UK",
        name                   = "United Kingdom",
        flag                   = "🇬🇧",
        frameworks             = ("UK_GDPR", "DPA2018", "NIS_REGULATIONS"),
        ai_regulations         = ("UK_AI_WHITEPAPER", "ICO_AI_GUIDANCE"),
        cloud_regions          = ("eu-west-2",),
        residency_required     = True,
        cross_border_restricted= True,
        adequacy_partners      = ("EU", "US", "CA", "AU"),
    ),

    "CA": Jurisdiction(
        code                   = "CA",
        name                   = "Canada",
        flag                   = "🇨🇦",
        frameworks             = ("PIPEDA", "CPPA", "PHIPA"),
        ai_regulations         = ("AIDA", "ISED_AI_GUIDANCE"),
        cloud_regions          = ("ca-central-1", "ca-west-1"),
        residency_required     = True,
        cross_border_restricted= True,
        adequacy_partners      = ("EU", "US", "UK"),
    ),

    "APAC_SG": Jurisdiction(
        code                   = "APAC_SG",
        name                   = "Singapore",
        flag                   = "🇸🇬",
        frameworks             = ("PDPA", "MAS_TRM", "CSA_FRAMEWORK"),
        ai_regulations         = ("IMDA_AI_GOVERNANCE", "MAS_FEAT"),
        cloud_regions          = ("ap-southeast-1",),
        residency_required     = True,
        cross_border_restricted= False,
        adequacy_partners      = ("EU", "US", "AU", "JP"),
    ),

    "AU": Jurisdiction(
        code                   = "AU",
        name                   = "Australia",
        flag                   = "🇦🇺",
        frameworks             = ("PRIVACY_ACT", "APRA_CPS234", "IRAP"),
        ai_regulations         = ("AUS_AI_ETHICS_PRINCIPLES", "ASIC_AI_GUIDANCE"),
        cloud_regions          = ("ap-southeast-2",),
        residency_required     = True,
        cross_border_restricted= False,
        adequacy_partners      = ("EU", "US", "UK", "CA"),
    ),

    "JP": Jurisdiction(
        code                   = "JP",
        name                   = "Japan",
        flag                   = "🇯🇵",
        frameworks             = ("APPI", "METI_SECURITY"),
        ai_regulations         = ("METI_AI_PRINCIPLES", "CSTI_AI_STRATEGY"),
        cloud_regions          = ("ap-northeast-1", "ap-northeast-3"),
        residency_required     = True,
        cross_border_restricted= True,
        adequacy_partners      = ("EU", "US", "UK", "AU"),
    ),

    "CH": Jurisdiction(
        code                   = "CH",
        name                   = "Switzerland",
        flag                   = "🇨🇭",
        frameworks             = ("FADP", "REVDSG"),
        ai_regulations         = ("CH_AI_GUIDELINES",),
        cloud_regions          = ("eu-central-2",),
        residency_required     = True,
        cross_border_restricted= True,
        adequacy_partners      = ("EU", "UK", "US"),
    ),
}

# ── Framework descriptions ────────────────────────────────────────────────────

FRAMEWORK_DESCRIPTIONS: dict[str, str] = {
    "GDPR":                  "EU General Data Protection Regulation (2016/679)",
    "NIS2":                  "EU Network and Information Security Directive 2",
    "DORA":                  "EU Digital Operational Resilience Act",
    "eIDAS":                 "EU Electronic Identification and Trust Services",
    "EU_AI_ACT":             "EU Artificial Intelligence Act (2024/1689)",
    "GPAI_CODE_OF_PRACTICE": "EU GPAI Model Code of Practice",
    "HIPAA":                 "US Health Insurance Portability and Accountability Act",
    "SOC2":                  "AICPA SOC 2 Type II",
    "FedRAMP":               "US Federal Risk and Authorization Management Program",
    "CCPA":                  "California Consumer Privacy Act",
    "NIST_CSF":              "NIST Cybersecurity Framework 2.0",
    "NIST_AI_RMF":           "NIST AI Risk Management Framework (AI 100-1)",
    "EO14110":               "US Executive Order on Safe AI (Oct 2023)",
    "UK_GDPR":               "UK General Data Protection Regulation",
    "DPA2018":               "UK Data Protection Act 2018",
    "PIPEDA":                "Canada Personal Information Protection and Electronic Documents Act",
    "CPPA":                  "Canada Consumer Privacy Protection Act (Bill C-27)",
    "PDPA":                  "Singapore Personal Data Protection Act",
    "PRIVACY_ACT":           "Australia Privacy Act 1988 (amended 2023)",
    "APPI":                  "Japan Act on the Protection of Personal Information",
    "FADP":                  "Switzerland Federal Act on Data Protection (revDSG)",
    "AIDA":                  "Canada Artificial Intelligence and Data Act",
}

# ── Compliance data classification matrix ─────────────────────────────────────
# Maps (data_classification, jurisdiction) → whether transfer is allowed

DataClass = str   # "PII" | "PHI" | "FINANCIAL" | "GENERAL" | "CLASSIFIED"

TRANSFER_RULES: dict[DataClass, dict[str, bool]] = {
    "CLASSIFIED": {j: False for j in JURISDICTIONS},  # never cross-border
    "PHI":        {
        "US": True, "EU": True, "UK": True, "CA": True,
        "APAC_SG": False, "AU": False, "JP": False, "CH": True,
    },
    "PII": {j: True for j in JURISDICTIONS},    # allowed but requires attestation
    "FINANCIAL": {j: True for j in JURISDICTIONS},
    "GENERAL":   {j: True for j in JURISDICTIONS},
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_jurisdiction(code: str) -> Jurisdiction | None:
    return JURISDICTIONS.get(code.upper())


def jurisdictions_with_adequacy(home: str) -> list[str]:
    """Return all jurisdictions that have an adequacy decision relative to *home*."""
    j = get_jurisdiction(home)
    if not j:
        return []
    return list(j.adequacy_partners)


def is_transfer_allowed(
    data_class:       DataClass,
    from_jurisdiction: str,
    to_jurisdiction:   str,
) -> bool:
    """
    Return True when transferring *data_class* from *from_jurisdiction* to
    *to_jurisdiction* is legally permitted under the configured rules.
    """
    if from_jurisdiction == to_jurisdiction:
        return True
    from_j = get_jurisdiction(from_jurisdiction)
    to_j   = get_jurisdiction(to_jurisdiction)
    if not from_j or not to_j:
        return False

    # Check TRANSFER_RULES matrix
    dc_rules = TRANSFER_RULES.get(data_class, {})
    if not dc_rules.get(to_jurisdiction, True):
        return False

    # Source jurisdiction with cross_border_restricted requires adequacy partner
    if from_j.cross_border_restricted:
        if to_jurisdiction not in from_j.adequacy_partners:
            return False

    return True
