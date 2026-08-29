from __future__ import annotations

import math

import pytest

from sih26145.ml.dns_features import FEATURE_NAMES, extract_dns_features


def test_example_domain_has_hand_derived_dns_features_v1() -> None:
    features = extract_dns_features("Example.COM.")

    assert features.schema_version == "dns_features_v1"
    assert features.domain == "example.com"
    assert features.summary_vector() == pytest.approx(
        (10.0, 2.0, 7.0, 5.0, 0.0, 0.0, 0.4, 0.8, 2.9219280948873623, 1.0, 3.0, 0.0)
    )


def test_digit_hyphen_and_run_features_are_bounded_ratios() -> None:
    features = extract_dns_features("a1-22.bb")

    assert features.summary_vector() == pytest.approx(
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


def test_model_vector_adds_bounded_deterministic_hashed_character_ngrams() -> None:
    first = extract_dns_features("example.com").as_vector()
    second = extract_dns_features("example.com").as_vector()

    assert len(FEATURE_NAMES) == 140
    assert len(first) == len(FEATURE_NAMES)
    assert first == second
    assert sum(first[12:]) == pytest.approx(1.0)
    assert all(0.0 <= value <= 1.0 for value in first[12:])


@pytest.mark.parametrize(
    "domain",
    ["bad..example", "_service.example", "caf\N{LATIN SMALL LETTER E WITH ACUTE}.example"],
)
def test_feature_extractor_rejects_names_outside_dns_event_contract(domain: str) -> None:
    with pytest.raises(ValueError):
        extract_dns_features(domain)
