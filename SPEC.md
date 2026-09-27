# headgate.egress/0.1
Steward: Caplifi Build

Gate id: `hg.egress`.

This document is the whole standard. A reference implementation sits beside it. An implementation that needs a vendor, a host, or a person named in order to run is outside this version.

## Terms

A **segment** is one presented unit of traffic. The length is an integer. Length zero is a segment.

A **peer discovery** is any check whose action is `discover`, `remote_service_discovery`, or `rsd`.

A **human seal** is a secret the deployment configures locally. The standard stores only an HMAC-SHA256 of that secret. The secret is not part of the specification.

A **channel** is any way out a deployment declares to the witness. A socket, a file, a letter, and a model reply are the same kind of fact. This specification names none of them.

## Rules

1. **Resting state is sealed.** Before any successful open, and after every close, admission and peer discovery are deny.
2. **Absence is sealed.** A missing state file, an unreadable file, a file that is not the expected record, or a record whose open is not matched by a receipt, is sealed.
3. **Empty segments are denied.** `admit` of length zero is deny in the resting state. The same deny applies to every positive length.
4. **Discovery is deny while sealed.** The three discovery actions above return deny. The peer is not present.
5. **Failed checks are deny.** If the check raises, the result is deny and the state is sealed. The caller does not receive a partial allow.
6. **Close is automatic and always takes effect.** `close` does not require the human seal. The sealed state is written first, even if the receipt cannot be written (code `sealed_unrecorded`).
7. **Open requires human seal.** `open` requires the deployment's configured seal. A missing configuration, a blank presentation, or a mismatch is deny, and the state stays sealed. The presented secret is not written to the state file or the receipt.
8. **Widening acts require a written receipt.** Open, seal, and rotate require the receipt to be written before the state changes. If the receipt cannot be written, the act is denied and the previous state remains.
9. **Discovery is recognized loosely; other actions abstain.** Case, surrounding spaces and hyphens do not change an action, so `RSD` and `remote-service-discovery` are discovery. An action that is not admission, discovery, open, or close produces `ABSTAIN`. Abstain grants nothing.
10. **Witness handles malformed channels.** Input is never coerced: a string where a boolean belongs, or a fractional, negative or infinite byte count, is unknown. Zero declared channels is `unknown`, never sealed. A declared channel is sealed only when it is down, blocking, and both byte counters are zero. Any other observation is leaking. A channel that is up means the peer may be seen. Malformed channels (non-boolean flags, negative or non-integer byte counts) are treated as unknown.
11. **Seal rotation requires current seal.** `init_seal` only works when no seal exists. `rotate` requires the current seal and the new seal.
12. **Hash-chained receipts.** Each receipt row carries `seq` and `prev` (sha256 of the previous line; first row's `prev` is 64 zeros). A broken chain means sealed.
13. **Open expiration.** `open` takes a TTL in seconds, at most 86400; after it passes, the gate is sealed. A longer TTL is deny.
14. **Torn receipt lines.** A torn final receipt line (no trailing newline) was never a record; it is set aside, not trusted.
15. **Decision allowed field.** Decisions carry `allowed` (true only for `ALLOW`). `ABSTAIN` is never ok and never allowed.

## Record

State file, JSON object:
- `protocol`: `headgate.egress/0.1`
- `state`: `sealed` or `open`
- `seal`: `auto` or `human`
- `when`: UTC timestamp
- `expires`: integer epoch seconds (Unix time) when the open state expires

Open is effective only when `state` is `open`, `seal` is `human`, the receipt chain is verified, the latest receipt is an allowed open, and its `seal_id` and `expires` match the current state.

Receipt line, JSON:
- `protocol`, `gate`, `verb`, `mood`, `code`, `when`
- `seq`: integer sequence number
- `prev`: sha256 hash of the previous line (first line's `prev` is 64 zeros)
- For open rows: `seal_id` (first 16 hex characters of the sha256 of the stored seal MAC; never the seal itself), `expires` (integer epoch seconds)

`verb` is `open`, `close`, `reseal`, or `seal`.

## Threat model

The gate protects against a caller that cannot write its home directory; a process that can rewrite every file there can rewrite any local record; isolate the home directory under a separate OS user when the caller is untrusted.

## Conformance

The reference tests are the conformance suite. A second implementation passes when those tests pass against its `admit`, `discover`, `open`, `close`, and `judge` without editing the tests except for the import path.

---

Copyright 2026 Caplifi Technologies. This specification text is licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Anyone may implement it.
