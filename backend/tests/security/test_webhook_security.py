import pytest

from app.integrations.destinations import signature, verify_signature

pytestmark = [pytest.mark.security, pytest.mark.notifications, pytest.mark.regression]


@pytest.mark.parametrize("age", [-301, -300, -1, 0, 1, 300, 301])
def test_hmac_timestamp_boundaries_cover_old_and_future_replays(age: int) -> None:
    key, stamp, body = "synthetic-signing-key", "1000", b'{"synthetic":true}'
    assert verify_signature(key, stamp, body, signature(key, stamp, body), now=1000 + age) is (
        abs(age) <= 300
    )


@pytest.mark.parametrize("change", ["key", "timestamp", "body", "algorithm", "digest", "missing"])
def test_hmac_authenticates_exact_bytes_and_rejects_wrong_inputs(change: str) -> None:
    key, stamp, body = "synthetic-signing-key", "1000", b'{"synthetic":true}'
    supplied = signature(key, stamp, body)
    if change == "key":
        key += "-wrong"
    elif change == "timestamp":
        stamp = "1001"
    elif change == "body":
        body += b"\n"
    elif change == "algorithm":
        supplied = supplied.replace("sha256", "SHA256")
    elif change == "digest":
        supplied = "sha256=" + "0" * 64
    else:
        supplied = ""
    assert not verify_signature(key, stamp, body, supplied, now=1000)


def test_hmac_never_authenticates_with_an_empty_configuration_key() -> None:
    assert not verify_signature("", "1000", b"{}", signature("", "1000", b"{}"), now=1000)
