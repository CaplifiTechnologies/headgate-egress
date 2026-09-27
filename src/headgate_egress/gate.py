"""Egress Headgate reference implementation.

Resting state is sealed. An empty segment is a byte. Discovery of a peer
is deny while sealed. Close is automatic and always takes effect. Open
requires a human seal that the deployment configures, and it expires.
Replacing the seal requires the current seal. Receipts are hash-chained.
A failed check is deny.

Threat model: this gate protects against a caller that cannot write the
gate's home directory. A process that can rewrite every file in that
directory can rewrite any local record. Isolate the home directory under
a separate OS user when the caller must not be trusted with it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

PROTOCOL = "headgate.egress/0.1"
GATE = "hg.egress"
DISCOVERY = frozenset({"discover", "remote_service_discovery", "rsd"})
MAX_TTL_SECONDS = 86400


def _norm_action(action: object) -> str:
    """Case, spaces and hyphens do not change what an action is: 'RSD ', 'remote-service-discovery' are discovery."""
    return str(action).strip().lower().replace("-", "_").replace(" ", "_") if isinstance(action, str) else ""
GENESIS = "0" * 64
DEFAULT_TTL_SECONDS = 3600


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resting() -> dict[str, Any]:
    """Policy. Independent of whatever the deployment last recorded."""
    return {
        "ok": True,
        "protocol": PROTOCOL,
        "gate": GATE,
        "state": "sealed",
        "empty_segments": "drop",
        "discovery": "deny",
        "open": "human_seal",
        "open_expires": True,
        "close": "auto",
        "seal_rotation": "requires_current_seal",
        "receipts": "hash_chained",
        "failed_check": "deny",
    }


@dataclass(frozen=True)
class Segment:
    length: int


@dataclass(frozen=True)
class Channel:
    name: str
    up: bool
    blocked: bool
    bytes_in: int = 0
    bytes_out: int = 0


@dataclass
class Decision:
    decision: str
    code: str
    state: str
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """True only when something may pass. The one field a caller gates on."""
        return self.decision == "ALLOW"

    @property
    def ok(self) -> bool:
        """The request did what was asked: ALLOW, or a SHUT that was asked for.
        ABSTAIN and DENY are never ok, so `if d.ok: send()` cannot leak."""
        return self.decision in ("ALLOW", "SHUT")

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = dict(self.extra)
        body.update({
            "ok": self.ok,
            "allowed": self.allowed,
            "protocol": PROTOCOL,
            "gate": GATE,
            "decision": self.decision,
            "code": self.code,
            "state": self.state,
        })
        return body


def _strict_channel(c: Any) -> bool:
    return (
        isinstance(c, Channel)
        and isinstance(c.name, str) and bool(c.name)
        and isinstance(c.up, bool) and isinstance(c.blocked, bool)
        and type(c.bytes_in) is int and type(c.bytes_out) is int
        and c.bytes_in >= 0 and c.bytes_out >= 0
    )


def judge(channels: list[Channel]) -> dict[str, Any]:
    """Pure witness. No declared channel, or any malformed one, is unknown, never sealed.
    Any iterable is read exactly once into a list, so a generator cannot be consumed by the check."""
    try:
        channels = list(channels)
    except TypeError:
        channels = []
    if not channels or not all(_strict_channel(c) for c in channels):
        return {
            "state": "unknown",
            "empty_segments": "unknown",
            "rsd_presence": "unknown",
            "leaks": [],
        }
    leaks: list[dict[str, str]] = []
    visible = False
    for channel in channels:
        if channel.up:
            visible = True
            leaks.append({"channel": channel.name, "why": "channel_up"})
        if channel.bytes_in > 0 or channel.bytes_out > 0:
            leaks.append({"channel": channel.name, "why": "bytes_passed"})
        if not channel.blocked:
            leaks.append({"channel": channel.name, "why": "not_blocking"})
    sealed = not leaks
    return {
        "state": "sealed" if sealed else "leaking",
        "empty_segments": "drop" if sealed else "may_pass",
        "rsd_presence": "absent" if not visible else "present",
        "leaks": leaks,
    }


def _deny(code: str, state: str = "sealed", **extra: Any) -> Decision:
    return Decision("DENY", code, state, extra)


def _mac(salt: bytes, seal: str) -> str:
    return hmac.new(salt, seal.encode("utf-8"), hashlib.sha256).hexdigest()


def _row_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class Gate:
    def __init__(self, home: Path | str, clock: Callable[[], float] = time.time):
        self.home = Path(home)
        self._clock = clock

    def _dir(self) -> Path:
        self.home.mkdir(parents=True, exist_ok=True)
        return self.home

    @contextmanager
    def _lock(self) -> Iterator[None]:
        directory = self._dir()
        handle = open(directory / "state.lock", "a", encoding="utf-8")
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _state_path(self) -> Path:
        return self.home / "state.json"

    def _receipt_path(self) -> Path:
        return self.home / "receipts.jsonl"

    def _seal_path(self) -> Path:
        return self.home / "seal.json"

    # ---- seal ---------------------------------------------------------------

    def _seal_record(self) -> dict[str, str] | None:
        try:
            data = json.loads(self._seal_path().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return None
        if not isinstance(data, dict) or data.get("kdf") != "hmac-sha256":
            return None
        salt, mac = data.get("salt"), data.get("mac")
        if not isinstance(salt, str) or not isinstance(mac, str) or len(mac) != 64:
            return None
        try:
            bytes.fromhex(salt)
        except ValueError:
            return None
        return {"salt": salt, "mac": mac}

    def _seal_matches(self, presented: str) -> bool:
        record = self._seal_record()
        if record is None:
            return False
        expect = _mac(bytes.fromhex(record["salt"]), presented)
        return hmac.compare_digest(expect, record["mac"])

    def _seal_id(self) -> str | None:
        record = self._seal_record()
        return hashlib.sha256(record["mac"].encode()).hexdigest()[:16] if record else None

    def _write_seal(self, presented: str) -> None:
        salt = secrets.token_bytes(32)
        body = {"kdf": "hmac-sha256", "salt": salt.hex(), "mac": _mac(salt, presented)}
        path = self._seal_path()
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    # ---- state --------------------------------------------------------------

    def _read_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self._state_path().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return {"state": "sealed", "protocol": PROTOCOL}
        if not isinstance(data, dict):
            return {"state": "sealed", "protocol": PROTOCOL}
        return data

    def _write_state(self, state: str, seal: str, expires: float | None = None) -> None:
        path = self._state_path()
        body: dict[str, Any] = {"protocol": PROTOCOL, "state": state, "seal": seal, "when": _now()}
        if expires is not None:
            body["expires"] = int(expires)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    # ---- receipts (hash chain) ---------------------------------------------

    def _chain(self) -> tuple[list[dict[str, Any]], str] | None:
        """Verified rows and the tip hash. None if the chain is broken or unreadable.
        A torn final line (no newline, never completed) is ignored, not trusted."""
        path = self._receipt_path()
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return [], GENESIS
        except (OSError, UnicodeError):
            return None
        lines = text.split("\n")
        complete = lines[:-1]  # the part after the last newline is torn or empty
        rows: list[dict[str, Any]] = []
        prev = GENESIS
        for seq, line in enumerate(complete):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(row, dict) or row.get("prev") != prev or row.get("seq") != seq:
                return None
            rows.append(row)
            prev = _row_hash(line)
        return rows, prev

    def _heal_torn_tail(self) -> bool:
        """Move an incomplete final line aside before appending. It was never a record."""
        path = self._receipt_path()
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if not data or data.endswith(b"\n"):
            return True
        cut = data.rfind(b"\n") + 1
        try:
            with open(self.home / "receipts.torn", "ab") as torn:
                torn.write(data[cut:] + b"\n")
            with open(path, "r+b") as fh:
                fh.truncate(cut)
        except OSError:
            return False
        return True

    def _append_receipt(self, verb: str, mood: str, code: str, **extra: Any) -> bool:
        if not self._heal_torn_tail():
            return False
        chain = self._chain()
        if chain is None:
            return False
        rows, tip = chain
        row = {
            "protocol": PROTOCOL,
            "gate": GATE,
            "seq": len(rows),
            "prev": tip,
            "verb": verb,
            "mood": mood,
            "code": code,
            "when": _now(),
        }
        row.update(extra)
        line = json.dumps(row, sort_keys=True)
        try:
            fd = os.open(self._receipt_path(), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            return False
        after = self._chain()
        return bool(after) and after[1] == _row_hash(line)

    def _open_effective(self) -> bool:
        data = self._read_state()
        if data.get("state") != "open" or data.get("seal") != "human":
            return False
        expires = data.get("expires")
        if not isinstance(expires, int) or self._clock() >= expires:
            return False
        seal_id = self._seal_id()
        if seal_id is None:
            return False
        chain = self._chain()
        if not chain or not chain[0]:
            return False
        last = chain[0][-1]
        return (
            last.get("verb") == "open"
            and last.get("mood") == "ALLOW"
            and last.get("seal_id") == seal_id
            and last.get("expires") == expires
        )

    def _guard(self, fn: Callable[[], Decision]) -> Decision:
        try:
            with self._lock():
                return fn()
        except Exception:
            return _deny("egress_error")

    # ---- verbs --------------------------------------------------------------

    def discover(self) -> Decision:
        def run() -> Decision:
            if self._open_effective():
                return Decision("ALLOW", "egress_open", "open", {"rsd_presence": "present"})
            return _deny("egress_sealed", rsd_presence="absent")

        return self._guard(run)

    def admit(self, segment: Segment) -> Decision:
        def run() -> Decision:
            if type(segment.length) is not int or segment.length < 0:
                return _deny("malformed_segment")
            if not self._open_effective():
                return _deny("egress_sealed", length=segment.length)
            return Decision("ALLOW", "egress_open", "open", {"length": segment.length})

        return self._guard(run)

    def check(self, action: str) -> Decision:
        def run() -> Decision:
            if _norm_action(action) in DISCOVERY:
                if self._open_effective():
                    return Decision("ALLOW", "egress_open", "open", {"rsd_presence": "present"})
                return _deny("egress_sealed", rsd_presence="absent")
            if _norm_action(action) == "admit":
                return _deny("segment_required")
            return Decision("ABSTAIN", "outside_gate", "open" if self._open_effective() else "sealed")

        return self._guard(run)

    def init_seal(self, seal: str) -> Decision:
        """First configuration only. Replacing a seal goes through rotate()."""

        def run() -> Decision:
            presented = seal.strip()
            if not presented:
                return _deny("human_seal_required")
            if self._seal_path().exists():
                return _deny("seal_exists_use_rotate", state="open" if self._open_effective() else "sealed")
            if not self._append_receipt("seal", "SET", "seal_configured"):
                return _deny("unrecorded")
            self._write_seal(presented)
            return Decision("SHUT", "seal_configured", "sealed")

        return self._guard(run)

    def rotate(self, current: str, new: str) -> Decision:
        def run() -> Decision:
            old, nxt = current.strip(), new.strip()
            if not old or not nxt:
                return _deny("human_seal_required")
            if self._open_effective():
                return _deny("seal_while_open", state="open")
            if not self._seal_matches(old):
                return _deny("seal_mismatch")
            if not self._append_receipt("seal", "ROTATE", "seal_rotated"):
                return _deny("unrecorded")
            self._write_seal(nxt)
            return Decision("SHUT", "seal_rotated", "sealed")

        return self._guard(run)

    def open(self, seal: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Decision:
        def run() -> Decision:
            presented = seal.strip()
            if not presented:
                return _deny("human_seal_required")
            if self._seal_record() is None:
                return _deny("seal_unconfigured")
            if type(ttl_seconds) is not int or ttl_seconds <= 0:
                return _deny("ttl_required")
            if ttl_seconds > MAX_TTL_SECONDS:
                return _deny("ttl_too_long", max_ttl_seconds=MAX_TTL_SECONDS)
            if not self._seal_matches(presented):
                return _deny("seal_mismatch")
            expires = int(self._clock()) + ttl_seconds
            if not self._append_receipt("open", "ALLOW", "egress_open", seal_id=self._seal_id(), expires=expires):
                return _deny("unrecorded")
            self._write_state("open", "human", expires)
            return Decision("ALLOW", "egress_open", "open", {"expires": expires})

        return self._guard(run)

    def close(self) -> Decision:
        """Always takes effect. The sealed state is written first; the receipt is best effort."""

        def run() -> Decision:
            state_written = True
            try:
                self._write_state("sealed", "auto")
            except OSError:
                state_written = False
            recorded = self._append_receipt("close", "SHUT", "egress_sealed")
            if state_written or recorded:
                return Decision("SHUT", "egress_sealed" if recorded else "sealed_unrecorded", "sealed")
            return _deny("close_failed", state="open" if self._open_effective() else "sealed")

        return self._guard(run)

    def reseal(self, channels: list[Channel], enforcer: Callable[[list[str]], None]) -> Decision:
        """Shut leaking channels. The witness's reading travels as `observed`; it never overwrites `state`.
        Receipts say what happened: an attempt row before the enforcer, then SHUT or DENY after it."""
        channels = list(channels) if not isinstance(channels, (str, bytes)) else []

        def run() -> Decision:
            if self._open_effective():
                return Decision("ABSTAIN", "already_open", "open")
            judged = judge(channels)
            report = {"observed": judged["state"], "leaks": judged["leaks"], "rsd_presence": judged["rsd_presence"]}
            if judged["state"] == "sealed":
                return Decision("SHUT", "already_sealed", "sealed", report)
            if judged["state"] != "leaking":
                return _deny("unknown_coverage", state="unknown", **report)
            leaking = sorted({leak["channel"] for leak in judged["leaks"]})
            if not self._append_receipt("reseal", "ATTEMPT", "reseal_attempt", channels=leaking):
                return _deny("unrecorded", state="unknown", **report)
            try:
                enforcer(leaking)
            except Exception:
                self._append_receipt("reseal", "DENY", "enforcer_failed", channels=leaking)
                return _deny("enforcer_failed", state="unknown", **report)
            self._write_state("sealed", "auto")
            self._append_receipt("reseal", "SHUT", "egress_sealed", channels=leaking)
            return Decision("SHUT", "egress_sealed", "sealed", report)

        return self._guard(run)
