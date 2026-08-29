"""Versioned lexical DNS features shared by training and runtime inference."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from sih26145.contracts.events import normalize_dns_name

FEATURE_SCHEMA_VERSION: Literal["dns_features_v1"] = "dns_features_v1"
FEATURE_NAMES = (
    "domain_length",
    "label_count",
    "longest_label_length",
    "mean_label_length",
    "digit_ratio",
    "hyphen_ratio",
    "vowel_ratio",
    "unique_character_ratio",
    "character_entropy_bits",
    "unique_bigram_ratio",
    "longest_consonant_run",
    "longest_digit_run",
)


def _longest_run(labels: list[str], predicate: Callable[[str], bool]) -> int:
    longest = 0
    for label in labels:
        current = 0
        for character in label:
            if predicate(character):
                current += 1
                longest = max(longest, current)
            else:
                current = 0
    return longest


@dataclass(frozen=True, slots=True)
class DnsLexicalFeatures:
    """Named `dns_features_v1` values for one normalized query name."""

    schema_version: Literal["dns_features_v1"]
    domain: str
    domain_length: int
    label_count: int
    longest_label_length: int
    mean_label_length: float
    digit_ratio: float
    hyphen_ratio: float
    vowel_ratio: float
    unique_character_ratio: float
    character_entropy_bits: float
    unique_bigram_ratio: float
    longest_consonant_run: int
    longest_digit_run: int

    def as_vector(self) -> tuple[float, ...]:
        """Return values in the immutable `FEATURE_NAMES` order."""

        return (
            float(self.domain_length),
            float(self.label_count),
            float(self.longest_label_length),
            self.mean_label_length,
            self.digit_ratio,
            self.hyphen_ratio,
            self.vowel_ratio,
            self.unique_character_ratio,
            self.character_entropy_bits,
            self.unique_bigram_ratio,
            float(self.longest_consonant_run),
            float(self.longest_digit_run),
        )


def extract_dns_features(domain: str) -> DnsLexicalFeatures:
    """Extract a finite lexical vector from one strict passive DNS name."""

    normalized = normalize_dns_name(domain)
    labels = normalized.split(".")
    compact = "".join(labels)
    length = len(compact)
    counts = Counter(compact)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    bigrams = [label[index : index + 2] for label in labels for index in range(len(label) - 1)]
    unique_bigram_ratio = len(set(bigrams)) / len(bigrams) if bigrams else 0.0
    vowels = frozenset("aeiou")

    return DnsLexicalFeatures(
        schema_version=FEATURE_SCHEMA_VERSION,
        domain=normalized,
        domain_length=length,
        label_count=len(labels),
        longest_label_length=max(map(len, labels)),
        mean_label_length=length / len(labels),
        digit_ratio=sum(character.isdigit() for character in compact) / length,
        hyphen_ratio=compact.count("-") / length,
        vowel_ratio=sum(character in vowels for character in compact) / length,
        unique_character_ratio=len(counts) / length,
        character_entropy_bits=entropy,
        unique_bigram_ratio=unique_bigram_ratio,
        longest_consonant_run=_longest_run(
            labels,
            lambda character: character.isalpha() and character not in vowels,
        ),
        longest_digit_run=_longest_run(labels, str.isdigit),
    )
