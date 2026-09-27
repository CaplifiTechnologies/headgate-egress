# Egress Headgate
Steward: Caplifi Build

Ditch AI names three gates. This package is the egress one: `headgate.egress/0.1`, gate `hg.egress`. Headgate Standard is the record: deterministic, no keys, append-only. Frontier Headgate is the API gate. This package does not include that wire.

A channel is any way out a deployment declares. This package names none.

Resting state is sealed.

While that state holds:

- No segment passes. A length of zero is still a segment.
- Discovery of a peer is deny.
- A missing, unreadable, or unrecorded state is sealed.
- A check that fails is deny.

Close is automatic. Open is a human seal chosen by the deployment. This package ships no seal, no host list, and no interface names.

A deployment is conformant when these tests pass against it. The witness agrees a channel is sealed only when that channel is down, every packet on it is dropped, and no bytes have moved. Declaring no channel is unknown, never sealed.

## Use

```bash
cd headgate-egress
PYTHONPATH=src python3 -m headgate_egress init-seal --home .egress
PYTHONPATH=src python3 -m headgate_egress rotate --home .egress
PYTHONPATH=src python3 -m headgate_egress open --home .egress --ttl 3600
PYTHONPATH=src python3 -m headgate_egress discover --home .egress
PYTHONPATH=src python3 -m headgate_egress admit --home .egress --length 0
PYTHONPATH=src python3 -m headgate_egress check --home .egress --action rsd
PYTHONPATH=src python3 -m headgate_egress close --home .egress
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`init-seal` and `open` read one line from stdin; `rotate` reads two (the current seal, then the new one). On a terminal the seal is not echoed. Each seal is hashed into the deployment directory and is not written back. Never put a seal on the command line.

An open expires after `--ttl` seconds (default 3600). Exit codes: 0 for ALLOW or SHUT, 1 for DENY, 3 for ABSTAIN.

Normative rules are in `SPEC.md`. The bench demo is `demo/index.html`. Anyone may implement this specification and this reference.

## Known limits (draft 0.1)

These are open. They are listed so nobody has to find them the hard way.

- **Pick a long random seal.** The seal is stored as a salted HMAC, not a slow password hash. A short seal can be guessed from `seal.json` offline. Failed opens are not yet written to the receipts and are not rate limited.
- **Expiry trusts the wall clock.** Setting the clock back can make an expired open count again until the next close. Opens are capped at 24 hours.
- **One user, one lock.** Any process that can read the home folder can hold the lock and make `close` wait. Real isolation needs the home folder under a separate OS user, with a small broker that callers talk to. This package does not ship that broker.
- **No fsync on state.** A power cut at the wrong moment can bring back the previous state file. The receipts are fsynced.

Reports of new ways to break a claim are welcome. They are how the draft gets better.

## License

Code: Apache License 2.0 (`LICENSE`). Specification text (`SPEC.md`): CC BY 4.0. Copyright 2026 Caplifi Technologies. See `NOTICE`.
