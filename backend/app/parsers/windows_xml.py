import xml.etree.ElementTree as ET
from typing import Any

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from app.core.errors import DomainError

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def xml_root(text: str) -> ET.Element:
    try:
        if len(text.encode("utf-8")) > 65_536:
            raise DomainError("Windows XML exceeds its byte limit")
        # Reject declarations at the parser, including UTF-16 code units disguised as JSON text.
        root = fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ET.ParseError, DefusedXmlException, UnicodeError) as exc:
        raise DomainError("Malformed Windows event XML") from exc
    pending = [(root, 1)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if depth > 12:
            raise DomainError("Windows XML exceeds its nesting limit")
        if nodes > 1024:
            raise DomainError("Windows XML exceeds its nodes limit")
        pending.extend((child, depth + 1) for child in node)
    return root


def event_data(text: str) -> dict[str, str]:
    root = xml_root(text)
    result: dict[str, str] = {}
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "Data":
            continue
        name = node.get("Name") or f"Data{len(result)}"
        if name in result:
            raise DomainError("Duplicate named Windows EventData field")
        result[name] = node.text or ""
    return result


def windows_xml(text: str) -> dict[str, Any]:
    root = xml_root(text)
    system = root.find(f"{NS}System")
    if root.tag != f"{NS}Event" or system is None:
        raise DomainError("Expected a Windows Event XML document")
    values: dict[str, Any] = {}
    for item in system:
        name = item.tag.removeprefix(NS)
        values[name] = dict(item.attrib) if item.attrib else item.text
    values["EventID"] = int(values["EventID"]) if str(values.get("EventID", "")).isdigit() else None
    return {"Event": {"System": values, "EventData": event_data(text)}, "raw_xml": text}
