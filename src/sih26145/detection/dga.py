"""Stateless local DGA inference for validated passive DNS events."""

from __future__ import annotations

from datetime import UTC, datetime

from sih26145.contracts.alerts import (
    AlertSource,
    AlertWindow,
    DetectorIdentity,
    DgaAlertV1,
    DgaEvidence,
    DgaLexicalEvidence,
    Severity,
)
from sih26145.contracts.events import DnsEventV1
from sih26145.ml.dga_model import DgaModel
from sih26145.ml.dns_features import extract_dns_features


class DgaDetector:
    """Classify each DNS request independently with one preloaded local model."""

    def __init__(self, *, model: DgaModel) -> None:
        self._model = model

    def process(self, event: DnsEventV1) -> DgaAlertV1 | None:
        """Return a typed alert when the model probability reaches its threshold."""

        probability = self._model.predict_probability(event.query_name)
        if probability < self._model.decision_threshold:
            return None

        features = extract_dns_features(event.query_name)
        observed_at = datetime.fromtimestamp(event.ts, UTC)
        evidence = DgaEvidence(
            query_name=event.query_name,
            query_type=event.query_type,
            dga_probability=probability,
            decision_threshold=self._model.decision_threshold,
            model_version=self._model.model_version,
            feature_schema_version=self._model.feature_schema_version,
            observed_span_seconds=0.0,
            lexical_features=DgaLexicalEvidence(
                domain_length=features.domain_length,
                label_count=features.label_count,
                longest_label_length=features.longest_label_length,
                mean_label_length=features.mean_label_length,
                digit_ratio=features.digit_ratio,
                hyphen_ratio=features.hyphen_ratio,
                vowel_ratio=features.vowel_ratio,
                unique_character_ratio=features.unique_character_ratio,
                character_entropy_bits=features.character_entropy_bits,
                unique_bigram_ratio=features.unique_bigram_ratio,
                longest_consonant_run=features.longest_consonant_run,
                longest_digit_run=features.longest_digit_run,
            ),
        )
        return DgaAlertV1(
            timestamp=observed_at,
            flow_id=event.uid,
            threat_class="DGA",
            protocol=event.transport,
            confidence=probability,
            severity=self._severity(probability),
            detector=DetectorIdentity(name="dga_logistic_regression", version="1.0.0"),
            source=AlertSource(ip=event.src_ip),
            window=AlertWindow(
                start=observed_at,
                end=observed_at,
                configured_seconds=0.0,
            ),
            evidence=evidence,
        )

    @staticmethod
    def _severity(probability: float) -> Severity:
        if probability < 0.85:
            return Severity.MEDIUM
        if probability < 0.95:
            return Severity.HIGH
        return Severity.CRITICAL
