import json
import math
from collections.abc import Hashable
from typing import Any

import regex
import yaml
from yaml.nodes import MappingNode, ScalarNode

from app.core.errors import DomainError

MAX_RULE_BYTES = 65_536
MAX_TEXT = 16_384
MAX_DEPTH = 12


def utf8_bytes(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeError as exc:
        raise DomainError("Text must contain valid Unicode scalar values") from exc


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DomainError(f"Duplicate key: {key[:80]}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise DomainError(f"Non-finite JSON number is not supported: {value}")


def check_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise DomainError(f"Input nesting exceeds {MAX_DEPTH} levels")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise DomainError("Object keys must be strings")
            if len(key) > 256:
                raise DomainError("Object key exceeds 256 characters")
            utf8_bytes(key)
            check_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            check_tree(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_TEXT:
            raise DomainError(f"Individual text field exceeds {MAX_TEXT} characters")
        utf8_bytes(value)
    elif isinstance(value, float) and not math.isfinite(value):
        raise DomainError("Non-finite numbers are not supported")
    elif not isinstance(value, str | int | float | bool | type(None)):
        raise DomainError("Only JSON-compatible scalar values are supported")


def json_loads(text: str) -> Any:
    try:
        value = json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError) as exc:
        raise DomainError("Malformed JSON or excessive nesting") from exc
    check_tree(value)
    return value


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        pairs = [
            (self.construct_object(key, deep=deep), self.construct_object(value, deep=deep))  # type: ignore[no-untyped-call]
            for key, value in node.value
        ]
        if any(not isinstance(key, str) for key, _ in pairs):
            raise DomainError("YAML mapping keys must be strings")
        return {key: value for key, value in unique_pairs(pairs).items()}


def _timestamp_as_text(loader: yaml.SafeLoader, node: ScalarNode) -> str:
    return loader.construct_scalar(node)


UniqueSafeLoader.add_constructor("tag:yaml.org,2002:timestamp", _timestamp_as_text)


def yaml_loads(text: str) -> dict[str, Any]:
    if len(utf8_bytes(text)) > MAX_RULE_BYTES:
        raise DomainError("Rule exceeds 64 KiB", 413, "size_limit")
    try:
        for token in yaml.scan(text):
            if isinstance(token, yaml.tokens.AliasToken | yaml.tokens.AnchorToken):
                raise DomainError("YAML anchors and aliases are not supported")
        value = yaml.load(text, Loader=UniqueSafeLoader)  # noqa: S506 - SafeLoader subclass
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        raise DomainError("Malformed or unsafe YAML") from exc
    if not isinstance(value, dict):
        raise DomainError("A rule must be a YAML mapping")
    check_tree(value)
    return value


def compile_pattern(pattern: str) -> regex.Pattern[str]:
    if len(pattern) > 256:
        raise DomainError("Regex patterns are limited to 256 characters")
    if regex.search(r"\\[1-9]|\(\?(?:[=!<]|P|R|\d)|\(\*|(?:\*|\+|\})[+*{]", pattern):
        raise DomainError(
            "Regex backreferences, lookarounds, recursion and nested repeats unsupported"
        )
    try:
        return regex.compile(pattern, regex.IGNORECASE | regex.VERSION1)
    except regex.error as exc:
        raise DomainError(f"Invalid regex: {exc}") from exc


def regex_search(pattern: regex.Pattern[str], value: str) -> bool:
    if len(value) > MAX_TEXT:
        raise DomainError("Regex input exceeds the text limit")
    try:
        return pattern.search(value, timeout=0.005) is not None
    except TimeoutError as exc:
        raise DomainError(
            "Regex evaluation exceeded 5 ms; simplify the rule", 422, "regex_timeout"
        ) from exc
