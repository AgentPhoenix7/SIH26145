# Task 6 report: native Zeek SYN-to-JSONL policy

## Implementation and inspection summary

Inspected the existing Task 6 policy and integration contract. The native Zeek
policy passively consumes PCAP packets, emits only originator TCP SYN records as
`tcp_syn_attempt_v1` JSONL, flushes each event, and emits one final ordered
`control_v1` end-of-stream record with the measured event count and final event
timestamp. It does not load logging frameworks, create output files, open
sockets, aggregate traffic, or initiate traffic toward observed addresses.

The existing Hatch wheel configuration packages the policy automatically as
package data; no no-op `pyproject.toml` change was needed. The integration test
was made type-correct by returning `list[StreamRecord]` and explicitly narrowing
SYN records before attribute access.

## Verification commands and outputs

All commands were run from the feature worktree with native Zeek resolved from
`PATH`.

* `UV_CACHE_DIR=/tmp/sih26145-uv-cache uv run pytest tests/integration/test_zeek_policy.py -v`
  * `7 passed in 1.26s`
* `UV_CACHE_DIR=/tmp/sih26145-uv-cache uv build && UV_CACHE_DIR=/tmp/sih26145-uv-cache uv run python -c 'from pathlib import Path; from zipfile import ZipFile; wheels=list(Path("dist").glob("*.whl")); assert len(wheels)==1; names=ZipFile(wheels[0]).namelist(); assert sum(name.endswith("emit_syn_attempts.zeek") for name in names)==1; print(wheels[0], "policy_count=1")'`
  * Successfully built `dist/sih26145-0.1.0.tar.gz` and `dist/sih26145-0.1.0-py3-none-any.whl`; output: `dist/sih26145-0.1.0-py3-none-any.whl policy_count=1`.
* `UV_CACHE_DIR=/tmp/sih26145-uv-cache uv run ruff check tests/integration/test_zeek_policy.py`
  * `All checks passed!`
* `UV_CACHE_DIR=/tmp/sih26145-uv-cache uv run mypy tests/integration/test_zeek_policy.py`
  * `Success: no issues found in 1 source file`
* `UV_CACHE_DIR=/tmp/sih26145-uv-cache uv run pytest`
  * `128 passed in 1.51s`
* `git diff --check`
  * Exit code 0; no output.

## TDD evidence

The following is prior-session evidence supplied in the Task 6 brief, not an
observation from this session: the focused integration test was first run RED
because `emit_syn_attempts.zeek` did not exist, then the native policy was
implemented and the seven focused tests passed GREEN. This session independently
reran the focused tests and observed 7 passing tests.

## Files changed

* `src/sih26145/zeek/emit_syn_attempts.zeek`
* `tests/integration/test_zeek_policy.py`
* This report file.

## Self-review

The policy uses `pkt$is_orig`, so SYN-ACK packets are excluded while repeated
SYN packet events retain Zeek's stable connection UID for downstream
deduplication. Explicit flushes preserve incremental delivery and the EOS
priority ensures the control record is emitted after packet events. The test
asserts no temporary Zeek output files, exact fixture counts, originator source,
stable retransmission UID, final EOS position, count, and timestamp.

## Concerns

No Task 6 defects remain. The complete suite and required static checks pass.
The policy intentionally covers only the native SYN observation boundary;
downstream deduplication and scan-window detection remain separate components.
