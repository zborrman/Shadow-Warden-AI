"""R8.5a - claims in a seller's own text that need proof or a registration."""
from __future__ import annotations

from warden.m2m_store.listing_lint import lint


def _terms(text: str) -> set[tuple[str, str]]:
    return {(f["term"], f["category"]) for f in lint({"description": text})}


def test_each_kind_of_claim_is_found_with_its_legal_basis():
    found = lint({"name": "Eco-friendly antibacterial board",
                  "description": "Non-toxic. Cures acne. Kills 99.9% of germs."})
    assert {(f["field"], f["category"]) for f in found} == {
        ("name", "environmental_claim"), ("name", "pesticide_claim"),
        ("description", "absolute_claim"), ("description", "disease_claim"),
        ("description", "pesticide_claim"),
    }
    assert all(f["basis"] for f in found)


def test_spelling_variants_are_one_finding():
    assert _terms("anti-bacterial, Antibacterial, ANTI BACTERIAL") == {("antibacterial", "pesticide_claim")}


def test_whole_words_only():
    # "treats" the claim, not "treatsy" or a word that merely contains it.
    assert _terms("Dog treatsy biscuits, retreats, greenhouse") == set()
    assert _terms("A green product") == {("green product", "environmental_claim")}


def test_plain_text_passes():
    assert lint({"name": "Ceramic mug, 350 ml", "description": "Dishwasher safe. Holds 350 ml."}) == []


def test_dog_treats_are_food_not_a_disease_claim():
    assert _terms("Chicken dog treats, 200 g") == set()


def test_treats_with_a_condition_is_a_claim():
    assert _terms("This balm treats eczema overnight") == {("treats eczema", "disease_claim")}
