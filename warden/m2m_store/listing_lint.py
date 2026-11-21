"""
warden/m2m_store/listing_lint.py
────────────────────────────────
Pre-flight check of a product's own text (stage R8.5a).

Flags wording that a regulator treats as a claim needing proof or a
registration - the kind of text marketplaces remove a listing over:

* pesticide claims (US EPA, FIFRA): "antibacterial", "kills germs" and the
  like make a product a pesticide unless it is registered;
* disease or drug claims (US FDA, EU cosmetics/medical rules): "cures",
  "treats", "prevents infection";
* environmental claims (US FTC Green Guides, EU 2024/825 on generic
  environmental claims): "eco-friendly", "biodegradable" without proof;
* absolute safety claims: "100% safe", "non-toxic".

It reads only the seller's own text and returns findings; it never edits,
blocks or publishes anything. The list is ours, built from those rules - not a
copy of any marketplace's internal filter, which is not public.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

# category -> (legal basis, {term: safer wording or ""})
_RULES: dict[str, tuple[str, dict[str, str]]] = {
    "pesticide_claim": (
        "US EPA (FIFRA): a product that claims to kill or repel germs or pests is a pesticide and must be registered.",
        {
            "antibacterial": "easy to clean", "anti-bacterial": "easy to clean",
            "antimicrobial": "easy to clean", "anti-microbial": "easy to clean",
            "antiviral": "", "anti-viral": "", "antifungal": "", "anti-fungal": "",
            "kills germs": "cleans", "kills bacteria": "cleans", "kills viruses": "",
            "kills 99.9%": "", "germ-free": "", "disinfects": "cleans", "disinfectant": "cleaner",
            "sanitizes": "cleans", "sanitizing": "cleaning", "mold-resistant": "", "mildew-resistant": "",
            "insect repellent": "", "repels mosquitoes": "", "pest control": "",
        },
    ),
    "disease_claim": (
        "US FDA / EU rules: a disease or treatment claim makes a product a drug or medical device.",
        {
            "cures": "", "cure for": "", "treatment for": "", "heals": "soothes",
            # "treats" alone is usually food ("dog treats"); with a condition it is a claim.
            "treats acne": "", "treats pain": "", "treats eczema": "", "treats psoriasis": "",
            "treats arthritis": "", "treats insomnia": "", "treats anxiety": "", "treats infection": "",
            "remedy": "", "prevents infection": "", "prevents disease": "", "fda approved": "",
            "clinically proven": "tested", "medical grade": "", "relieves pain": "", "pain relief": "",
            "anti-inflammatory": "", "boosts immunity": "", "detox": "",
        },
    ),
    "environmental_claim": (
        "US FTC Green Guides / EU Directive 2024/825: generic green claims need specific proof.",
        {
            "eco-friendly": "made from 80% recycled plastic (state the fact)",
            "environmentally friendly": "state the specific fact", "green product": "",
            "biodegradable": "", "compostable": "", "carbon neutral": "", "climate neutral": "",
            "sustainable": "state the specific fact", "zero waste": "", "planet friendly": "",
        },
    ),
    "absolute_claim": (
        "Absolute safety wording is a claim a seller must be able to prove for every use.",
        {
            "non-toxic": "", "nontoxic": "", "100% safe": "", "completely safe": "",
            "chemical-free": "", "harmless": "", "hypoallergenic": "",
        },
    ),
}


@dataclass(frozen=True)
class Finding:
    term: str
    category: str
    field: str
    basis: str
    suggestion: str


def _pattern(term: str) -> re.Pattern[str]:
    # Whole words, any case, hyphen or space between parts.
    body = r"[\s-]?".join(re.escape(p) for p in re.split(r"[\s-]", term))
    return re.compile(rf"(?<![\w-]){body}(?![\w-])", re.IGNORECASE)


_COMPILED = [(cat, term, sug, _pattern(term), basis)
             for cat, (basis, terms) in _RULES.items()
             for term, sug in terms.items()]


def lint(fields: dict[str, str]) -> list[dict[str, str]]:
    """Findings for each named text field, one per term per field, in field order."""
    out: list[Finding] = []
    for field, text in fields.items():
        seen: set[str] = set()
        for cat, term, sug, pat, basis in _COMPILED:
            # "anti-bacterial" and "antibacterial" are one finding, not two.
            key = re.sub(r"[\s-]", "", term)
            if key in seen or not text or not pat.search(text):
                continue
            seen.add(key)
            out.append(Finding(term, cat, field, basis, sug))
    return [asdict(f) for f in out]
