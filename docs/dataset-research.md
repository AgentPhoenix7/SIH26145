# SIH26145 Dataset and External-Resource Research

Research date: 2026-08-26

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

## Remaining Research

- Identify a licensable benign-domain source and one or more DGA-family sources
  suitable for family-grouped evaluation.
- Check the licences and safe local execution requirements of the exact traffic
  generators selected for each scenario.
- Decide whether encrypted-session coverage can be demonstrated honestly with
  lab-generated TLS metadata before feature freeze.
- Re-check the official SIH26145 page for a corrected resource link before the
  August 30 feature freeze.

## Evidence Notes

- The official SIH page was fetched and the exact SIH26145 HTML segment was
  inspected on 2026-08-26.
- The unrelated SIH-hosted PDF was downloaded only to `/tmp` for metadata/text
  inspection; it was not added to the repository.
- No attack generator was run, no traffic was sent, and no dataset was imported
  during this research phase.
