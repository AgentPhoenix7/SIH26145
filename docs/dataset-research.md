# SIH26145 Dataset and External-Resource Research

Research date: 2026-08-26; DNS/DGA source decision verified 2026-08-29

## Conclusion

No downloadable official SIH26145 dataset or external dataset URL was found.
The authoritative SIH 2026 problem-statement page labels a field as
`Dataset Link`, but for SIH26145 that field contains a truncated text recipe
for generating synthetic/lab traffic. The page renders that text as a malformed
hyperlink; it does not identify a usable dataset artifact.

This means the MVP needs a controlled, labelled lab dataset, supplemented by
appropriately licensed public domain lists or fingerprints only where their
features can be reproduced by the passive runtime pipeline.

## Authoritative Source

- Official page: <https://sih.gov.in/sih2026PS>
- Problem statement: `SIH26145`
- Title: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*
- Organization: National Technical Research Organisation (NTRO)
- Category: Software
- Theme: Blockchain & Cybersecurity
- Page checked: 2026-08-26

The official description requires all six threat categories, read-only ingest,
no TLS/QUIC payload decryption, incremental processing with bounded alert
latency, a demonstrated throughput target, and structured evidence-bearing
alerts.

The official `Dataset Link` field contains only the following visible guidance:

> a) Synthetic and lab-generated traffic: benign load from iperf3, Ostinato,
> or TRex; attack traffic from hping3 (SYN/UDP floods), Slowloris (slow HTTP
> exhaustion), dnscat2/iodine (DNS tunnelling), and DGA samples from published
> algorithms (e.g., via DGArchive) or a sandboxed C2 emulator for realistic
> beaconing timing. b) Feature extraction: Extract flow

The text ends at `Extract flow` on the official page. Inspection of the page's
HTML found no valid external-resource URL in this field. The generated `href`
contains the guidance text itself, so it cannot be treated as a download link.

## False Lead Rejected

Web search surfaced <https://sih.gov.in/dataset/Data_set.pdf>. It is genuinely
hosted on the SIH domain, but it is unrelated to SIH26145:

- Title in document: `SIH 2024 Data Set Link`
- Created: 2024-08-28
- Author metadata: AICTE
- Contents: one page of SVAMITVA drone image/vector downloads (`.tif` and
  `.shp`) for Indian states
- Cyber-traffic content: none

It must not be downloaded or described as the SIH26145 dataset.

## Resource Characteristics

| Question | Finding |
|---|---|
| Official downloadable artifact | None found |
| PCAP files | Not provided |
| NetFlow/IPFIX/sFlow records | Not provided |
| CSV or precomputed features | Not provided |
| Domain lists | Not provided; DGArchive is mentioned only as an example source |
| Schema or labels | Not provided |
| Dataset-specific licence | None stated because no dataset artifact is linked |
| Usage restrictions | Each selected generator and supplemental source must be reviewed separately before use |

A public GitHub mirror of the 2026 problem catalogue was used only to locate
and cross-check the record. Its stated CC-BY-4.0 licence is not evidence of a
licence for any future training dataset.

## Threat-Coverage Gap Analysis

| Threat class required by SIH26145 | Covered by official generation guidance? | Current implication |
|---|---:|---|
| SYN/UDP DDoS | Yes | Generate only inside an isolated local lab and capture passively |
| Botnet C2 beaconing | Yes | Use a sandboxed timing emulator; preserve jitter and run-level labels |
| DGA/DNS tunnelling | Yes | Generate tunnelling traffic locally; review provenance/licensing of any domain corpus |
| Encrypted-session malware metadata | No explicit generator | Defer until core detectors are stable, or create a controlled metadata scenario |
| Reconnaissance/port scanning | No explicit generator | Add an isolated scan scenario because this is Milestone 1 |
| Data exfiltration | No explicit generator | Add a controlled asymmetric-transfer scenario |

Slowloris is suggested by the resource guidance but is not one of the six
named threat classes. It should not displace the required MVP coverage.

## Training and Runtime Feature Parity

The lack of an official precomputed feature table is beneficial for parity: the
same versioned extractor can process both replayed lab captures and operational
stream events. A model must use only fields reproducible from passive runtime
observations.

Initial shared schemas should remain small:

- `connection_event_v1`: timestamp, source/destination addresses and ports,
  protocol, TCP state/flags when observable, packet/byte counts, duration.
- `dns_event_v1`: timestamp, flow identity, client/server, query name, query
  type, response metadata when observable.
- `alert_v1`: timestamp, flow identifier, threat class, confidence, severity,
  detector/model version, observation window, and measured evidence.

Do not train from convenient CSV columns that the streaming ingest path cannot
produce.

## Recommended Dataset Decision

Use a hybrid dataset strategy:

1. Generate small, deterministic benign and attack PCAPs on an isolated Docker
   network, beginning with benign connection attempts and port scanning.
2. Record scenario-level ground truth before capture: scenario ID, class,
   generator, UTC start/end, endpoints, parameters, capture filename, and notes.
3. Feed every capture through the same incremental event and feature path used
   by replay/demo inference.
4. Split ML data by scenario/run and, for DGA, by domain family rather than by
   random row.
5. Keep PCAPs and large derived data out of Git; commit manifests, tiny test
   fixtures, schemas, and reproducible generation commands.
6. Review and record the licence and provenance of each supplemental domain or
   fingerprint source before incorporating it.

## Milestone 3 DNS/DGA Source Decision

The following sources were verified before any corpus was imported:

| Role | Exact source | Provenance and licence | Format and use | Redistribution / limitations |
|---|---|---|---|---|
| Benign-domain proxy | Majestic Million, `https://downloads.majestic.com/majestic_million.csv` | The live Majestic page stated **Creative Commons Attribution 3.0 Unported** and identified a list generated on 2026-08-29. | Approximately 80 MB CSV. The preparation tool selects at most 20,000 unique normalized domains and records the downloaded file's SHA-256 and retrieval time. | Attribute Majestic. Keep the full snapshot out of Git. Popularity is not proof of benignness; rankings are time-varying and can include compromised or abused domains. |
| DGA-family examples | `https://github.com/baderj/domain_generation_algorithms`, pinned commit `0faef452d267a62a94124ef2806bc4a72e0913bd` | Repository `LICENSE` is **GNU GPL version 2**. The pinned tree exposes family-specific Python implementations and generated example-domain text files. | A local detached checkout supplies only explicitly selected family-labelled example lists; the preparation tool caps each family at 2,000 valid unique domains and records file hashes/counts. | Keep the checkout and full lists out of Git. Preserve attribution and revision. Do not copy upstream code into this project. Generated examples are synthetic algorithm outputs, not observed infections; no claim is made that trained weights remove source-licence obligations. |

The Majestic page's licence statement was observed at lines surrounding its CSV download link, and the DGA revision was resolved with `git ls-remote` before download. The model will use only normalized query-name features that the passive `dns_event_v1` runtime can reproduce. Family-disjoint DGA evaluation and stable hash-split unique benign domains prevent direct row leakage; they do not prove generalization to every unseen DGA or production DNS population.

### Imported Snapshot and Selection Evidence

After the provenance gate, the sources were acquired only for offline training under ignored `data/dns/`:

| Artifact | Current recorded evidence |
| --- | --- |
| Majestic snapshot | 80,119,152 bytes; SHA-256 `210cfa378d1c6b03338ff6950b3ab0fa20a6cd52c76b5a84f467207281822ba1`; 20,000 selected unique valid domains |
| DGA checkout | Detached revision `0faef452d267a62a94124ef2806bc4a72e0913bd`; families `banjori`, `chinad`, `fobber`, `kraken_v1`, `simda`, `tempedreve`, `tinba`, and `tufik`; 7,723 selected domains |
| Prepared dataset | 27,723 rows; SHA-256 `4001f5a52bc01fee60157d55531d6a1731d72804f103c00b17ead70efe64a582`; zero discarded duplicates and zero invalid selected rows |

The full CSV, checkout, generated lists, and prepared training CSV remain ignored and are not redistributed. The committed model metadata preserves source URLs, licences, revision, selected file hashes/counts, and dataset hash. The synthetic replay query `x9q7z8v6k5j4m3n2.example` is hand-authored under the reserved `.example` TLD and was confirmed absent from the prepared training CSV.

## Remaining Research

- Check the licences and safe local execution requirements of the exact traffic
  generators selected for each scenario.
- Re-check the official SIH26145 page for a corrected resource link before the
  August 30 feature freeze.

## Evidence Notes

- The official SIH page was fetched and the exact SIH26145 HTML segment was
  inspected on 2026-08-26.
- The unrelated SIH-hosted PDF was downloaded only to `/tmp` for metadata/text
  inspection; it was not added to the repository.
- No attack generator was run and no traffic was sent. Corpus acquisition occurred only after this documented provenance gate; the ignored source files were used for offline preparation and training, not runtime inference.
