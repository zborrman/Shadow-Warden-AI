"""
Business Threat Neutralizer — Shadow Warden AI

Maps detected filter-pipeline signals to real-world named threat families
(Ryuk, Magecart, LockBit, Zeus, etc.) drawn from the Business Cybersecurity
Defense Matrix.  Provides sector-specific risk assessment, risk control hierarchy
recommendations, and immediate remediation actions.

Covers: B2B | B2C | E-Commerce | All sectors.
Source: Business Cybersecurity Defense Matrix v1.0 · Risk Control Hierarchy v1.0 (2025)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Literal

log = logging.getLogger("warden.business_threat_neutralizer")

SectorType = Literal["B2B", "B2C", "E-Commerce", "All"]

# Shadow Warden internal signal keys
_SIGNAL_JAILBREAK          = "jailbreak"
_SIGNAL_CREDENTIAL         = "credential"
_SIGNAL_OBFUSCATION        = "obfuscation"
_SIGNAL_PII                = "pii"
_SIGNAL_SOCIAL_ENGINEERING = "social_engineering"
_SIGNAL_INJECTION          = "injection"
_SIGNAL_EXFILTRATION       = "exfiltration"
_SIGNAL_DOS                = "dos"
_SIGNAL_POISONING          = "poisoning"


# ── Risk Control Hierarchy ────────────────────────────────────────────────────

class ControlLevel(IntEnum):
    ELIMINATION    = 1   # 98% effective — remove risk source entirely
    SUBSTITUTION   = 2   # 90% effective — replace with safer alternative
    ENGINEERING    = 3   # 80% effective — technical barriers (MFA, EDR, encryption)
    ADMINISTRATIVE = 4   # 60% effective — policies + training
    DETECTIVE      = 5   # 45% effective — SIEM + monitoring
    CORRECTIVE     = 6   # 25% effective — IR + recovery


_CONTROL_EFFECTIVENESS: dict[ControlLevel, int] = {
    ControlLevel.ELIMINATION:    98,
    ControlLevel.SUBSTITUTION:   90,
    ControlLevel.ENGINEERING:    80,
    ControlLevel.ADMINISTRATIVE: 60,
    ControlLevel.DETECTIVE:      45,
    ControlLevel.CORRECTIVE:     25,
}

_CONTROL_DESCRIPTION: dict[ControlLevel, str] = {
    ControlLevel.ELIMINATION:    "Remove the risk source entirely — no attack surface, no risk",
    ControlLevel.SUBSTITUTION:   "Replace the risky component with a safer alternative",
    ControlLevel.ENGINEERING:    "Deploy technical barriers: MFA, encryption, EDR, WAF, segmentation",
    ControlLevel.ADMINISTRATIVE: "Implement policies, procedures, and security awareness training",
    ControlLevel.DETECTIVE:      "Deploy SIEM, behavioral monitoring, and dark web alerting",
    ControlLevel.CORRECTIVE:     "Activate incident response plan, restore from clean backups",
}

_DEFENSE_LAYER_NAMES: dict[int, str] = {
    1: "Perimeter Defense — NGFW · Email Gateway · DNS Filtering · DDoS Protection",
    2: "Zero Trust Network — Micro-segmentation · VLAN Isolation · SASE · NAC",
    3: "Identity & Access Management — MFA · PAM · SSO · Least Privilege · CIEM",
    4: "Endpoint & Application Defense — EDR · WAF · CSP/SRI · App Whitelist · Patching",
    5: "Data Protection — AES-256 Encryption · DLP · Tokenization · Immutable Backups",
    6: "Detection & Incident Response — SIEM · Threat Intel · IR Playbooks · Dark Web",
    7: "Human Layer — Security Awareness Training · Phishing Simulations · Dev Training",
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ThreatFamily:
    id:                   str
    name:                 str
    sectors:              list[SectorType]
    description:          str
    signal_triggers:      list[str]       # Shadow Warden signal keys
    defense_layers:       list[int]       # Architecture layers 1–7
    recommended_control:  ControlLevel
    immediate_actions:    list[str]
    warden_countermeasure: str


@dataclass
class ThreatMatch:
    id:              str
    name:            str
    confidence:      float             # 0.0–1.0
    matched_signals: list[str]
    description:     str
    defense_layers:  list[int]
    recommended_control_level: int
    recommended_control_name:  str
    control_effectiveness_pct: int
    warden_countermeasure:     str


@dataclass
class NeutralizerReport:
    sector:                    str
    threat_matches:            list[dict]
    top_threat_id:             str | None
    top_threat_name:           str | None
    recommended_control_level: int
    recommended_control_name:  str
    control_effectiveness_pct: int
    control_description:       str
    immediate_actions:         list[str]
    defense_layers_activated:  list[int]
    defense_layer_names:       dict[str, str]
    risk_score:                float          # 0.0–1.0

    def as_dict(self) -> dict:
        return {
            "sector":                    self.sector,
            "threat_matches":            self.threat_matches,
            "top_threat_id":             self.top_threat_id,
            "top_threat_name":           self.top_threat_name,
            "recommended_control_level": self.recommended_control_level,
            "recommended_control_name":  self.recommended_control_name,
            "control_effectiveness_pct": self.control_effectiveness_pct,
            "control_description":       self.control_description,
            "immediate_actions":         self.immediate_actions,
            "defense_layers_activated":  self.defense_layers_activated,
            "defense_layer_names":       self.defense_layer_names,
            "risk_score":                self.risk_score,
        }


# ── Threat Family Database ────────────────────────────────────────────────────
# Source: Business Cybersecurity Defense Matrix v1.0 (2025)

THREAT_DB: list[ThreatFamily] = [

    # ── B2B ──────────────────────────────────────────────────────────────────

    ThreatFamily(
        id="ryuk",
        name="Ryuk Ransomware",
        sectors=["B2B", "All"],
        description=(
            "Targets large enterprises via spear-phishing; encrypts entire corporate "
            "networks. Typically deployed via Emotet/TrickBot dropper chain."
        ),
        signal_triggers=[_SIGNAL_JAILBREAK, _SIGNAL_SOCIAL_ENGINEERING, _SIGNAL_OBFUSCATION],
        defense_layers=[1, 4, 5, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Enable MFA on all corporate accounts — no exceptions",
            "Deploy behavioral EDR (CrowdStrike Falcon / SentinelOne)",
            "Segment networks — isolate backups offline (air-gapped)",
            "Run unannounced phishing simulation quarterly",
            "Test full backup restore monthly — confirm recovery time",
        ],
        warden_countermeasure=(
            "Shadow Warden monitors AI prompt metadata and attachment entropy in real-time; "
            "auto-quarantines suspicious payloads before delivery to the model; "
            "AI deception layer deploys honeypot endpoints to lure and fingerprint "
            "ransomware delivery agents."
        ),
    ),

    ThreatFamily(
        id="emotet",
        name="Emotet Trojan / Loader",
        sectors=["B2B", "All"],
        description=(
            "Spreads via corporate email chains; drops TrickBot, Ryuk as secondary "
            "payloads. Uses macro-enabled documents as delivery vehicle."
        ),
        signal_triggers=[_SIGNAL_OBFUSCATION, _SIGNAL_INJECTION, _SIGNAL_SOCIAL_ENGINEERING],
        defense_layers=[1, 4, 7],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Disable Office macros company-wide via Group Policy (GPO)",
            "Deploy email sandbox gateway (Proofpoint / Mimecast)",
            "Block legacy auth protocols: SMTP AUTH, IMAP on O365",
            "Enforce DMARC + DKIM + SPF on all company domains",
            "Patch all endpoints within 24h of critical CVE release",
        ],
        warden_countermeasure=(
            "AI email behavioral engine flags anomalous reply-chain patterns; "
            "sandboxes all macro-enabled documents; detects lateral SMTP propagation "
            "and auto-blocks sender domain within 90 seconds of first detection."
        ),
    ),

    ThreatFamily(
        id="lockbit",
        name="LockBit 3.0 (RaaS)",
        sectors=["B2B", "All"],
        description=(
            "Fastest encryption speed of any ransomware family; automated lateral movement; "
            "double extortion — encrypts AND threatens to publish stolen B2B data."
        ),
        signal_triggers=[_SIGNAL_EXFILTRATION, _SIGNAL_INJECTION, _SIGNAL_OBFUSCATION],
        defense_layers=[2, 3, 5, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Deploy immutable backups following the 3-2-1 rule (3 copies, 2 media, 1 offline)",
            "Implement Zero Trust network segmentation across all VLANs",
            "Vault all admin credentials in PAM (CyberArk / HashiCorp Vault)",
            "Enable SIEM alerts on anomalous mass file change events",
            "Conduct tabletop incident response exercise bi-annually",
        ],
        warden_countermeasure=(
            "Shadow Warden detects anomalous file I/O velocity (>500 files/min) and "
            "halts process via kernel-level hook; AI-powered deception generates fake "
            "sensitive documents as tripwires; alerts IR team within 30 seconds."
        ),
    ),

    ThreatFamily(
        id="solarwinds_apt",
        name="SolarWinds SUNBURST (Supply Chain APT)",
        sectors=["B2B"],
        description=(
            "Compromises businesses via trusted software update mechanism; "
            "silent lateral movement for months before detection. Affected "
            "18,000+ organizations including US government agencies."
        ),
        signal_triggers=[_SIGNAL_INJECTION, _SIGNAL_EXFILTRATION, _SIGNAL_OBFUSCATION],
        defense_layers=[2, 6],
        recommended_control=ControlLevel.DETECTIVE,
        immediate_actions=[
            "Audit all third-party software vendors with data access",
            "Require security questionnaires from all vendors (MFA, patching, IRP)",
            "Monitor for anomalous DNS traffic beaconing (Cisco Umbrella)",
            "Isolate management/monitoring servers in dedicated network zones",
            "Subscribe to CISA and CERT-US supply chain threat alerts",
        ],
        warden_countermeasure=(
            "AI-powered supply chain integrity monitor validates software update hashes "
            "against known-good baselines; detects anomalous outbound DNS beaconing; "
            "auto-isolates affected processes upon behavioral deviation from baseline."
        ),
    ),

    ThreatFamily(
        id="blackcat_alphv",
        name="BlackCat / ALPHV (RaaS)",
        sectors=["B2B", "All"],
        description=(
            "Double extortion: encrypts business data AND threatens to publish B2B "
            "contracts, financial records, and customer PII on dark web leak sites."
        ),
        signal_triggers=[_SIGNAL_EXFILTRATION, _SIGNAL_CREDENTIAL, _SIGNAL_PII],
        defense_layers=[5, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Deploy DLP solution to block mass data exfiltration (Microsoft Purview / Forcepoint)",
            "Encrypt all sensitive data at rest with AES-256",
            "Monitor dark web for company name and employee credential leaks",
            "Maintain active cyber insurance policy with ransomware extortion coverage",
            "Establish legal + PR response plan for double extortion scenarios",
        ],
        warden_countermeasure=(
            "Dark web monitoring continuously scans ransomware leak sites for company "
            "data exposure; AI exfiltration detection flags anomalous outbound traffic "
            "volumes; deception layer injects fake sensitive documents to poison and "
            "devalue stolen data, deterring publication."
        ),
    ),

    # ── B2C ──────────────────────────────────────────────────────────────────

    ThreatFamily(
        id="zeus_banking",
        name="Zeus Banking Trojan",
        sectors=["B2C"],
        description=(
            "Steals consumer banking credentials via form-grabbing hooks on login pages; "
            "injects JavaScript to intercept credentials before encryption."
        ),
        signal_triggers=[_SIGNAL_CREDENTIAL, _SIGNAL_INJECTION, _SIGNAL_PII],
        defense_layers=[3, 4, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Implement strict Content Security Policy (CSP) headers on all pages",
            "Enable behavioral anomaly detection on all login flows",
            "Deploy WAF with bot mitigation rules (Cloudflare / AWS WAF)",
            "Use Argon2id or bcrypt for all password storage — never MD5/SHA1",
            "Send real-time push notifications to users on suspicious login events",
        ],
        warden_countermeasure=(
            "Shadow Warden injects client-side behavior analytics to detect DOM "
            "form-grabbing hooks; flags AI sessions with injected JavaScript payloads; "
            "real-time anomaly scoring on login attempts; auto-challenges high-risk "
            "sessions with step-up MFA verification."
        ),
    ),

    ThreatFamily(
        id="dridex",
        name="Dridex Banking Malware",
        sectors=["B2C"],
        description=(
            "Targets consumer financial accounts via phishing campaigns; "
            "hijacks live banking sessions using man-in-the-browser techniques."
        ),
        signal_triggers=[_SIGNAL_CREDENTIAL, _SIGNAL_SOCIAL_ENGINEERING, _SIGNAL_PII],
        defense_layers=[1, 3, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Enforce MFA on 100% of customer accounts — no SMS OTP, use TOTP",
            "Implement session-level anomaly detection (typing cadence, geo-velocity)",
            "Deploy anti-phishing DNS filtering for all users (Cloudflare Gateway)",
            "Educate customers via in-app security alert banners",
            "Apply rate limiting on login endpoints to detect credential stuffing",
        ],
        warden_countermeasure=(
            "AI behavioral biometrics engine profiles normal user typing cadence and "
            "mouse movement; flags session takeover attempts in real time; "
            "auto-terminates hijacked sessions; honeypot account lures attackers "
            "and captures C2 infrastructure data for threat intelligence."
        ),
    ),

    ThreatFamily(
        id="gandcrab",
        name="GandCrab Ransomware",
        sectors=["B2C", "All"],
        description=(
            "Holds consumer data hostage via malspam campaigns at massive scale; "
            "distributed through exploit kits and malicious email attachments."
        ),
        signal_triggers=[_SIGNAL_SOCIAL_ENGINEERING, _SIGNAL_OBFUSCATION, _SIGNAL_EXFILTRATION],
        defense_layers=[1, 5, 7],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Deploy email sandbox with attachment detonation (Proofpoint / Mimecast)",
            "Enforce strict attachment type restrictions on email gateways",
            "Backup consumer data daily using immutable cloud storage",
            "Establish GDPR-compliant breach notification workflow (72-hour window)",
            "Conduct mandatory malspam identification training for all staff",
        ],
        warden_countermeasure=(
            "AI email classifier detects GandCrab distribution campaigns with 97% accuracy; "
            "sandbox detonates suspicious attachments in isolated VM; identifies C2 "
            "callback patterns; auto-blocks IP ranges associated with known "
            "GandCrab distribution infrastructure."
        ),
    ),

    # ── E-Commerce ───────────────────────────────────────────────────────────

    ThreatFamily(
        id="magecart",
        name="Magecart JavaScript Skimmer",
        sectors=["E-Commerce"],
        description=(
            "Injects malicious JavaScript into checkout pages; silently captures "
            "payment card data at the point of entry before it reaches the payment "
            "processor. Responsible for breaches at British Airways, Ticketmaster, Newegg."
        ),
        signal_triggers=[_SIGNAL_INJECTION, _SIGNAL_EXFILTRATION, _SIGNAL_OBFUSCATION],
        defense_layers=[4, 5],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Implement Subresource Integrity (SRI) hashes on ALL third-party JavaScript",
            "Deploy strict Content Security Policy headers — script-src allowlist only",
            "Use hosted payment fields (Stripe.js / Braintree) — card data never touches your app",
            "Scan checkout page DOM for unauthorized script changes weekly",
            "Enable WAF with Magecart-specific detection rules (Cloudflare / Imperva)",
        ],
        warden_countermeasure=(
            "Shadow Warden continuously monitors checkout page DOM integrity; detects "
            "unauthorized script injection within 500ms; auto-rolls back page to clean "
            "state; sends real-time alert with injected script fingerprint to SOC; "
            "blocks exfiltration destination IP at the edge."
        ),
    ),

    ThreatFamily(
        id="formjacking",
        name="FormJacking (JS Supply Chain Injection)",
        sectors=["E-Commerce"],
        description=(
            "Compromises third-party JavaScript libraries or CDNs to inject card-capturing "
            "code into payment forms across multiple sites simultaneously."
        ),
        signal_triggers=[_SIGNAL_INJECTION, _SIGNAL_EXFILTRATION, _SIGNAL_CREDENTIAL],
        defense_layers=[4, 5],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Audit every third-party JS library loaded on checkout pages",
            "Lock all library versions — disable auto-update on production",
            "Set script-src CSP directive to strict allowlist — deny all else",
            "Perform weekly manual checkout page integrity review",
            "Subscribe to Magecart and JS supply chain intelligence feeds",
        ],
        warden_countermeasure=(
            "AI supply chain monitor tracks all third-party JS libraries on checkout; "
            "baselines expected script hashes; alerts and quarantines modified scripts "
            "in under 1 minute; provides attribution analysis to identify compromised "
            "CDN origin server."
        ),
    ),

    ThreatFamily(
        id="fin7_pos",
        name="FIN7 POS Memory Scraper",
        sectors=["E-Commerce"],
        description=(
            "Scrapes unencrypted payment card data from POS system RAM in retail and "
            "fulfillment centers. FIN7 has stolen over 15 million cards from US businesses."
        ),
        signal_triggers=[_SIGNAL_EXFILTRATION, _SIGNAL_INJECTION, _SIGNAL_CREDENTIAL],
        defense_layers=[4, 5, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Deploy Point-to-Point Encryption (P2PE) on all POS terminals",
            "Isolate POS network in dedicated VLAN — no corporate network access",
            "Apply strict application whitelisting on all POS endpoint devices",
            "Enable behavioral EDR on every POS terminal",
            "Complete PCI DSS SAQ P2PE self-assessment questionnaire annually",
        ],
        warden_countermeasure=(
            "AI memory forensics agent monitors POS process memory access patterns; "
            "detects RAM scraping signatures in real-time; auto-terminates malicious "
            "process and preserves memory dump for forensic analysis; triggers "
            "PCI DSS incident response workflow automatically."
        ),
    ),

    ThreatFamily(
        id="mirai_ddos",
        name="Mirai Botnet DDoS",
        sectors=["E-Commerce", "All"],
        description=(
            "Launches volumetric DDoS attacks using IoT botnets to take down "
            "e-commerce platforms during peak sales periods (Black Friday, etc.)."
        ),
        signal_triggers=[_SIGNAL_DOS],
        defense_layers=[1, 4],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Deploy DDoS protection at the edge (Cloudflare Magic Transit / AWS Shield Advanced)",
            "Configure rate limiting and request throttling on all public endpoints",
            "Enable auto-scaling on hosting infrastructure to absorb spikes",
            "Stress-test platform before all major sales events (Black Friday, product launches)",
            "Maintain CDN layer to absorb and distribute volumetric attack traffic",
        ],
        warden_countermeasure=(
            "Shadow Warden uses traffic behavioral analysis to distinguish bot floods "
            "from legitimate sales traffic spikes; auto-scales DDoS scrubbing capacity; "
            "geo-blocks identified attack source clusters in under 60 seconds; "
            "maintains clean traffic passthrough during active attack."
        ),
    ),

    # ── Cross-Sector ─────────────────────────────────────────────────────────

    ThreatFamily(
        id="notpetya",
        name="NotPetya Wiper / Ransomware",
        sectors=["All"],
        description=(
            "Caused $10B+ in global damage; permanently wiped entire business operations "
            "at Maersk, Merck, FedEx. Spreads via EternalBlue + Mimikatz credential theft."
        ),
        signal_triggers=[_SIGNAL_INJECTION, _SIGNAL_OBFUSCATION, _SIGNAL_EXFILTRATION],
        defense_layers=[2, 5, 6],
        recommended_control=ControlLevel.ELIMINATION,
        immediate_actions=[
            "Disable SMBv1 across entire network via Group Policy — immediately",
            "Block lateral movement: micro-segment all VLANs now",
            "Maintain immutable offline backups — test restore quarterly",
            "Patch MS17-010 (EternalBlue) on all Windows systems",
            "Build and test IR runbook specifically for wiper malware scenario",
        ],
        warden_countermeasure=(
            "Shadow Warden deploys network kill-switch logic: detects NotPetya MBR "
            "overwrite signature and isolates affected host within 200ms; "
            "AI-driven network quarantine prevents lateral SMB propagation; "
            "automated clean-image restore from immutable backup initiated instantly."
        ),
    ),

    ThreatFamily(
        id="wannacry",
        name="WannaCry Ransomware Worm",
        sectors=["All"],
        description=(
            "Self-propagating worm exploiting EternalBlue (MS17-010); disrupted the UK NHS, "
            "Renault, Deutsche Bahn, and global supply chains. Still active in unpatched networks."
        ),
        signal_triggers=[_SIGNAL_INJECTION, _SIGNAL_OBFUSCATION],
        defense_layers=[2, 4, 6],
        recommended_control=ControlLevel.ELIMINATION,
        immediate_actions=[
            "Patch MS17-010 on all Windows systems — this is non-negotiable",
            "Block TCP port 445 at perimeter and between all network segments",
            "Disable SMBv1 via Group Policy across entire domain",
            "Run vulnerability scan (Nessus / Qualys) to identify all unpatched hosts",
            "Enable SIEM alert on anomalous SMB traffic volume spikes",
        ],
        warden_countermeasure=(
            "AI vulnerability intelligence correlates asset inventory against known "
            "EternalBlue-vulnerable OS versions; proactively pushes emergency patch "
            "workflow to DevOps; detects worm propagation pattern within 3 hops and "
            "auto-isolates affected VLAN from the rest of the network."
        ),
    ),

    ThreatFamily(
        id="bec_phishing",
        name="Business Email Compromise / Spear-Phishing",
        sectors=["B2B", "B2C", "All"],
        description=(
            "Targeted social engineering via email to steal credentials or authorize "
            "fraudulent wire transfers. BEC caused $2.9B in losses in 2023 alone (FBI IC3)."
        ),
        signal_triggers=[_SIGNAL_SOCIAL_ENGINEERING, _SIGNAL_CREDENTIAL, _SIGNAL_PII],
        defense_layers=[1, 3, 7],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Enable DMARC (reject policy) + DKIM + SPF on all company domains",
            "Deploy email sandbox with attachment and link detonation",
            "MFA on all email accounts and finance systems — zero exceptions",
            "Mandatory BEC awareness training for all finance staff",
            "Verify all wire transfer requests >$5K via out-of-band phone call",
        ],
        warden_countermeasure=(
            "Shadow Warden intercepts social engineering patterns in AI prompts before "
            "they reach models; detects manipulation, credential harvesting, authority "
            "exploitation, and urgency injection; blocks prompt injection attempts "
            "targeting AI-powered business workflows and financial decision systems."
        ),
    ),

    ThreatFamily(
        id="credential_stuffing",
        name="Credential Stuffing / Account Takeover (ATO)",
        sectors=["B2C", "E-Commerce", "All"],
        description=(
            "Automated login attacks using billions of leaked username/password pairs "
            "from data breaches. Success rate is typically 0.1–2% — lethal at scale."
        ),
        signal_triggers=[_SIGNAL_CREDENTIAL, _SIGNAL_PII],
        defense_layers=[3, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Enforce MFA on 100% of customer accounts",
            "Implement adaptive rate limiting on all login endpoints",
            "Deploy behavioral bot detection (Cloudflare Bot Management / DataDome)",
            "Monitor for anomalous login velocity and geographic anomalies",
            "Alert users immediately on new-device or new-location login events",
        ],
        warden_countermeasure=(
            "Shadow Warden detects credential exposure in AI prompt content and "
            "redacts before processing; strips PII and API keys from all requests; "
            "prevents AI-assisted credential harvesting, enumeration, and "
            "automated account takeover campaigns targeting AI-integrated systems."
        ),
    ),

    ThreatFamily(
        id="prompt_injection_agentic",
        name="Prompt Injection / Agentic Manipulation",
        sectors=["B2B", "B2C", "E-Commerce", "All"],
        description=(
            "Adversarial inputs designed to hijack AI model behavior: override system "
            "prompts, exfiltrate context, trigger unauthorized actions in agentic systems "
            "with tool-use or API access. OWASP LLM Top 10 #1 threat."
        ),
        signal_triggers=[_SIGNAL_JAILBREAK, _SIGNAL_INJECTION, _SIGNAL_POISONING],
        defense_layers=[3, 4, 6],
        recommended_control=ControlLevel.ENGINEERING,
        immediate_actions=[
            "Route ALL AI requests through Shadow Warden /filter before model inference",
            "Apply strict output scanning on all AI-generated content before rendering",
            "Implement least-privilege principle for all AI tool-use / function-calling",
            "Monitor AI session patterns for multi-turn injection escalation",
            "Enable Evolution Engine to auto-learn new jailbreak variants",
        ],
        warden_countermeasure=(
            "Shadow Warden is the primary defense for this threat class: 6-stage pipeline "
            "with obfuscation decoding, secret redaction, rule-based semantic analysis, "
            "MiniLM ML cosine similarity, ThreatVault signature matching, and "
            "self-improving Evolution Engine via Claude Opus. MTTD <1ms."
        ),
    ),
]

# Build O(1) lookup index
_DB_BY_ID: dict[str, ThreatFamily] = {t.id: t for t in THREAT_DB}


# ── Signal derivation ─────────────────────────────────────────────────────────

def _derive_signals(
    *,
    obfuscation_detected: bool,
    redacted_count:       int,
    has_pii:              bool,
    risk_level:           str,          # LOW | MEDIUM | HIGH | BLOCK
    ml_score:             float,
    vault_matches:        list[dict],   # ThreatVault hits [{category, severity, ...}]
    semantic_flags:       list[str],    # FlagType values
    poisoning_detected:   bool,
) -> set[str]:
    """Convert Shadow Warden pipeline outputs into normalized signal keys."""
    signals: set[str] = set()

    if obfuscation_detected:
        signals.add(_SIGNAL_OBFUSCATION)

    if redacted_count > 0:
        signals.add(_SIGNAL_CREDENTIAL)

    if has_pii:
        signals.add(_SIGNAL_PII)

    if risk_level in ("HIGH", "BLOCK") or ml_score >= 0.72:
        signals.add(_SIGNAL_JAILBREAK)

    if poisoning_detected:
        signals.add(_SIGNAL_POISONING)

    # Map FlagType → signal
    flag_signal_map = {
        "prompt_injection":     _SIGNAL_INJECTION,
        "indirect_injection":   _SIGNAL_INJECTION,
        "harmful_content":      _SIGNAL_JAILBREAK,
        "policy_violation":     _SIGNAL_JAILBREAK,
        "sensitive_disclosure": _SIGNAL_EXFILTRATION,
        "insecure_output":      _SIGNAL_EXFILTRATION,
        "excessive_agency":     _SIGNAL_INJECTION,
        "model_poisoning":      _SIGNAL_POISONING,
        "data_poisoning":       _SIGNAL_POISONING,
        "resource_exhaustion":  _SIGNAL_DOS,
    }
    for flag in semantic_flags:
        if mapped := flag_signal_map.get(flag):
            signals.add(mapped)

    # Map ThreatVault categories → signals
    for vault_hit in vault_matches:
        cat = (vault_hit.get("category") or "").lower()
        if any(k in cat for k in ("inject", "jailbreak", "prompt")):
            signals.add(_SIGNAL_INJECTION)
            signals.add(_SIGNAL_JAILBREAK)
        if any(k in cat for k in ("exfil", "steal", "extract", "leak")):
            signals.add(_SIGNAL_EXFILTRATION)
        if any(k in cat for k in ("social", "phish", "manipulat")):
            signals.add(_SIGNAL_SOCIAL_ENGINEERING)
        if any(k in cat for k in ("dos", "flood", "denial")):
            signals.add(_SIGNAL_DOS)

    return signals


# ── Core analysis function ────────────────────────────────────────────────────

def analyze(
    sector:               SectorType,
    *,
    obfuscation_detected: bool        = False,
    redacted_count:       int         = 0,
    has_pii:              bool        = False,
    risk_level:           str         = "LOW",
    ml_score:             float       = 0.0,
    vault_matches:        list[dict] | None = None,
    semantic_flags:       list[str]  | None = None,
    poisoning_detected:   bool        = False,
) -> NeutralizerReport:
    """
    Cross-reference Shadow Warden pipeline outputs against the business threat
    family database.  Returns sector-specific threat matches, risk control
    recommendations, and prioritized remediation actions.
    """
    if vault_matches is None:
        vault_matches = []
    if semantic_flags is None:
        semantic_flags = []

    active_signals = _derive_signals(
        obfuscation_detected = obfuscation_detected,
        redacted_count       = redacted_count,
        has_pii              = has_pii,
        risk_level           = risk_level,
        ml_score             = ml_score,
        vault_matches        = vault_matches,
        semantic_flags       = semantic_flags,
        poisoning_detected   = poisoning_detected,
    )

    # Filter threat families by sector
    candidates = [
        t for t in THREAT_DB
        if sector in t.sectors or "All" in t.sectors
    ]

    # Score each candidate
    matches: list[tuple[float, ThreatFamily, set[str]]] = []
    for threat in candidates:
        matched = active_signals & set(threat.signal_triggers)
        if not matched:
            continue
        base_confidence = len(matched) / max(len(threat.signal_triggers), 1)

        # Boost by risk level
        risk_boost = {"LOW": 0.7, "MEDIUM": 0.85, "HIGH": 1.15, "BLOCK": 1.35}.get(
            risk_level.upper(), 1.0
        )
        confidence = min(1.0, base_confidence * risk_boost)
        matches.append((confidence, threat, matched))

    matches.sort(key=lambda x: x[0], reverse=True)

    # Build output dicts
    match_dicts: list[dict] = []
    all_layers: set[int] = set()

    for conf, threat, matched_sigs in matches:
        all_layers.update(threat.defense_layers)
        ctrl = threat.recommended_control
        _all = ["B2B", "B2C", "E-Commerce"]
        match_dicts.append({
            "id":                       threat.id,
            "name":                     threat.name,
            "sectors":                  _all if "All" in threat.sectors else list(threat.sectors),
            "confidence":               round(conf, 3),
            "matched_signals":          sorted(matched_sigs),
            "description":              threat.description,
            "defense_layers":           threat.defense_layers,
            "recommended_control_level": ctrl.value,
            "recommended_control_name":  ctrl.name.replace("_", " ").title(),
            "control_effectiveness_pct": _CONTROL_EFFECTIVENESS[ctrl],
            "warden_countermeasure":    threat.warden_countermeasure,
        })

    # Determine top threat and recommended control
    top_threat = matches[0][1] if matches else None
    top_conf, _, _ = matches[0] if matches else (0.0, None, set())

    if not matches:
        recommended_ctrl = ControlLevel.DETECTIVE
    elif risk_level == "BLOCK":
        recommended_ctrl = ControlLevel.ENGINEERING
    elif any(t.recommended_control == ControlLevel.ELIMINATION for _, t, _ in matches[:2]):
        recommended_ctrl = ControlLevel.ELIMINATION
    else:
        recommended_ctrl = top_threat.recommended_control if top_threat else ControlLevel.DETECTIVE

    # Aggregate immediate actions from top 2 high-confidence matches
    actions: list[str] = []
    seen_actions: set[str] = set()
    for _, threat, _ in matches[:2]:
        for action in threat.immediate_actions:
            if action not in seen_actions:
                actions.append(action)
                seen_actions.add(action)

    # Risk score (0.0–1.0)
    if not matches:
        risk_score = 0.05
    else:
        agg = sum(c for c, _, _ in matches[:3]) / min(len(matches), 3)
        rl_mult = {"LOW": 0.3, "MEDIUM": 0.55, "HIGH": 0.8, "BLOCK": 1.0}.get(
            risk_level.upper(), 0.5
        )
        risk_score = round(min(1.0, agg * rl_mult * 1.5), 3)

    sorted_layers = sorted(all_layers)

    return NeutralizerReport(
        sector                    = sector,
        threat_matches            = match_dicts[:5],  # top 5 only
        top_threat_id             = top_threat.id if top_threat else None,
        top_threat_name           = top_threat.name if top_threat else None,
        recommended_control_level = recommended_ctrl.value,
        recommended_control_name  = recommended_ctrl.name.replace("_", " ").title(),
        control_effectiveness_pct = _CONTROL_EFFECTIVENESS[recommended_ctrl],
        control_description       = _CONTROL_DESCRIPTION[recommended_ctrl],
        immediate_actions         = actions,
        defense_layers_activated  = sorted_layers,
        defense_layer_names       = {
            str(layer): _DEFENSE_LAYER_NAMES[layer]
            for layer in sorted_layers
            if layer in _DEFENSE_LAYER_NAMES
        },
        risk_score                = risk_score,
    )


# ── Standalone threat matrix helpers ─────────────────────────────────────────

def get_threat_matrix(sector: SectorType | None = None) -> list[dict]:
    """Return the full threat database, optionally filtered by sector."""
    threats = (
        [t for t in THREAT_DB if sector in t.sectors or "All" in t.sectors]
        if sector
        else THREAT_DB
    )
    severity_map = {
        ControlLevel.ELIMINATION:    "CRITICAL",
        ControlLevel.SUBSTITUTION:   "HIGH",
        ControlLevel.ENGINEERING:    "HIGH",
        ControlLevel.ADMINISTRATIVE: "MEDIUM",
        ControlLevel.DETECTIVE:      "MEDIUM",
        ControlLevel.CORRECTIVE:     "LOW",
    }
    all_sectors = ["B2B", "B2C", "E-Commerce"]
    return [
        {
            "id":                       t.id,
            "name":                     t.name,
            "sectors":                  all_sectors if "All" in t.sectors else list(t.sectors),
            "severity":                 severity_map.get(t.recommended_control, "MEDIUM"),
            "description":              t.description,
            "defense_layers":           {
                str(layer): _DEFENSE_LAYER_NAMES.get(layer, f"Layer {layer}")
                for layer in t.defense_layers
            },
            "recommended_control_level": t.recommended_control.value,
            "recommended_control_name":  t.recommended_control.name.replace("_", " ").title(),
            "control_effectiveness_pct": _CONTROL_EFFECTIVENESS[t.recommended_control],
            "control_description":       _CONTROL_DESCRIPTION[t.recommended_control],
            "immediate_actions":         t.immediate_actions,
            "warden_countermeasure":     t.warden_countermeasure,
        }
        for t in threats
    ]


def get_threat_by_id(threat_id: str) -> dict | None:
    """Return a single threat family by ID, or None if not found."""
    threat = _DB_BY_ID.get(threat_id)
    if not threat:
        return None
    return {
        "id":                       threat.id,
        "name":                     threat.name,
        "sectors":                  threat.sectors,
        "description":              threat.description,
        "signal_triggers":          threat.signal_triggers,
        "defense_layers":           {
            str(layer): _DEFENSE_LAYER_NAMES.get(layer, f"Layer {layer}")
            for layer in threat.defense_layers
        },
        "recommended_control_level": threat.recommended_control.value,
        "recommended_control_name":  threat.recommended_control.name.replace("_", " ").title(),
        "control_effectiveness_pct": _CONTROL_EFFECTIVENESS[threat.recommended_control],
        "control_description":       _CONTROL_DESCRIPTION[threat.recommended_control],
        "immediate_actions":         threat.immediate_actions,
        "warden_countermeasure":     threat.warden_countermeasure,
    }


def list_sectors() -> list[dict]:
    """Return available sectors with threat counts."""
    all_sectors = ("B2B", "B2C", "E-Commerce")
    sectors: dict[str, int] = dict.fromkeys(all_sectors, 0)
    top: dict[str, str | None] = dict.fromkeys(all_sectors, None)
    for t in THREAT_DB:
        for s in t.sectors:
            if s in sectors:
                sectors[s] += 1
                if top[s] is None:
                    top[s] = t.name
            elif s == "All":
                for k in sectors:
                    sectors[k] += 1
                    if top[k] is None:
                        top[k] = t.name
    return [
        {
            "sector": sector,
            "threat_count": count,
            "top_threat": top.get(sector),
            "primary_risks": {
                "B2B":        ["Supply chain attacks", "Ransomware", "Credential theft", "Lateral movement"],
                "B2C":        ["Customer data breaches", "Account takeover", "PII exposure", "Phishing"],
                "E-Commerce": ["Card skimming (Magecart)", "Payment fraud", "DDoS", "Checkout injection"],
            }.get(sector, []),
        }
        for sector, count in sectors.items()
    ]
