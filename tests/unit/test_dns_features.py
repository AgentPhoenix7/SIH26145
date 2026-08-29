from __future__ import annotations

import math

import pytest

from sih26145.ml.dns_features import extract_dns_features


def test_example_domain_has_hand_derived_dns_features_v1() -> None:
    features = extract_dns_features("Example.COM.")

    assert features.schema_version == "dns_features_v1"
    assert features.domain == "example.com"
    assert features.as_vector() == pytest.approx(
        (10.0, 2.0, 7.0, 5.0, 0.0, 0.0, 0.4, 0.8, 2.9219280948873623, 1.0, 3.0, 0.0)
    )


def test_digit_hyphen_and_run_features_are_bounded_ratios() -> None:
    features = extract_dns_features("a1-22.bb")

    assert features.as_vector() == pytest.approx(
        (
            7.0,
            2.0,
            5.0,
            3.5,
            3.0 / 7.0,
            1.0 / 7.0,
            1.0 / 7.0,
            5.0 / 7.0,
            2.2359263506290326,
            1.0,
            2.0,
            2.0,
        )
    )


def test_repeated_bigrams_reduce_unique_bigram_ratio() -> None:
    features = extract_dns_features("aaaa.com")

    assert features.unique_bigram_ratio == pytest.approx(3.0 / 5.0)
    assert math.isfinite(features.character_entropy_bits)


@pytest.mark.parametrize(
    "domain",
    ["bad..example", "_service.example", "caf\N{LATIN SMALL LETTER E WITH ACUTE}.example"],
)
def test_feature_extractor_rejects_names_outside_dns_event_contract(domain: str) -> None:
    with pytest.raises(ValueError):
        extract_dns_features(domain)
