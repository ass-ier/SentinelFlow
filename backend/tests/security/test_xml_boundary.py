from pathlib import Path

import pytest

from app.core.config import ROOT
from app.core.errors import DomainError
from app.parsers.windows_xml import xml_root

pytestmark = [pytest.mark.security, pytest.mark.regression, pytest.mark.parser]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"])
def test_xml_entity_declaration_is_rejected_in_every_input_encoding(encoding: str) -> None:
    source = (ROOT / "test-data/security/entity.xml").read_text()
    disguised = source.encode(encoding).decode("latin1")
    with pytest.raises(DomainError):
        xml_root(disguised)


@pytest.mark.parametrize("depth", [13, 3000])
def test_xml_nesting_is_bounded(depth: int) -> None:
    with pytest.raises(DomainError, match="nesting"):
        xml_root("<x>" * depth + "</x>" * depth)


def test_xml_node_count_is_bounded_even_when_bytes_are_small() -> None:
    with pytest.raises(DomainError, match="nodes"):
        xml_root("<x>" + "<a/>" * 1024 + "</x>")


@pytest.mark.parametrize("value", ["\ud800", "\udfff", "\x00", "\x01"])
def test_xml_invalid_unicode_is_a_controlled_input_error(value: str) -> None:
    with pytest.raises(DomainError):
        xml_root(f"<x>{value}</x>")


def test_external_entity_never_reads_a_file_or_resolves_a_network(
    tmp_path: Path, monkeypatch
) -> None:
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: pytest.fail("No DNS is allowed"))
    marker = tmp_path / "owned-fixture.txt"
    marker.write_text("synthetic-file-must-not-be-read")
    for target in (marker.as_uri(), "https://example.invalid/synthetic-only"):
        with pytest.raises(DomainError):
            xml_root(f'<!DOCTYPE x [<!ENTITY p SYSTEM "{target}">]><x>&p;</x>')


def test_bounded_benign_unicode_and_metadata_are_preserved() -> None:
    node = xml_root('<x origin="synthetic"><a>\u03b1 &amp; \u03b2</a></x>')
    assert node.attrib == {"origin": "synthetic"}
    assert node[0].text == "\u03b1 & \u03b2"
