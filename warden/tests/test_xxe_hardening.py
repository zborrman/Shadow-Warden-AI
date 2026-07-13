"""
SR-7 — XXE hardening (found by turning semgrep on: 6 blocking findings).

Every XML document these modules parse is attacker-influenced — a SAML assertion posted
to the ACS endpoint, or an external threat/ArXiv feed. stdlib `xml.etree` resolves
external entities, so those parsers were vulnerable to XXE: local-file exfiltration
(`file:///etc/passwd`), SSRF via entity URLs, and billion-laughs DoS.

All four call sites now use defusedxml, which refuses entity declarations outright.
"""
from __future__ import annotations

import pytest
from defusedxml.common import EntitiesForbidden

from warden.auth.saml import _xml_fromstring as saml_parse
from warden.brain.threat_feed import _xml_fromstring as feed_parse
from warden.threat_intel.sources import _xml_fromstring as intel_parse

_XXE = """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""

_PARSERS = [
    pytest.param(saml_parse,  id="saml"),        # attacker posts the assertion
    pytest.param(feed_parse,  id="threat_feed"), # external feed
    pytest.param(intel_parse, id="threat_intel"),# external Atom/ArXiv feed
]


@pytest.mark.parametrize("parse", _PARSERS)
def test_external_entity_is_refused(parse):
    """The classic XXE file-exfiltration payload must not parse at all."""
    with pytest.raises(EntitiesForbidden):
        parse(_XXE)


@pytest.mark.parametrize("parse", _PARSERS)
def test_billion_laughs_is_refused(parse):
    """Entity-expansion DoS must be refused rather than expanded."""
    with pytest.raises(EntitiesForbidden):
        parse(_BILLION_LAUGHS)


@pytest.mark.parametrize("parse", _PARSERS)
def test_benign_xml_still_parses(parse):
    """The hardening must not break ordinary parsing."""
    root = parse("<root><item>ok</item></root>")
    assert root.tag == "root"
    assert root.find("item").text == "ok"
