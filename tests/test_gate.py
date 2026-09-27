from __future__ import annotations

import json
import os
import time
import tempfile
import unittest
from pathlib import Path

decorator = lambda f: f

from headgate_egress.gate import PROTOCOL, Channel, Gate, Segment, judge, GATE

SEAL = "example-seal"


class EgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.gate = Gate(self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _files(self) -> str:
        parts: list[str] = []
        for path in self.home.rglob("*"):
            if path.is_file() and path.name != "state.lock":
                parts.append(path.read_text(encoding="utf-8"))
        return "\n".join(parts)

    def test_resting_policy_is_sealed(self) -> None:
        from headgate_egress.gate import resting

        body = resting()
        self.assertEqual(body["protocol"], PROTOCOL)
        self.assertEqual(body["state"], "sealed")
        self.assertEqual(body["empty_segments"], "drop")
        self.assertEqual(body["discovery"], "deny")
        self.assertEqual(body["open"], "human_seal")
        self.assertEqual(body["close"], "auto")

    def test_missing_state_denies_discovery_and_segments(self) -> None:
        found = self.gate.discover()
        empty = self.gate.admit(Segment(0))
        full = self.gate.admit(Segment(8))
        self.assertEqual(found.decision, "DENY")
        self.assertEqual(found.code, "egress_sealed")
        self.assertEqual(found.extra["rsd_presence"], "absent")
        self.assertEqual(empty.decision, "DENY")
        self.assertEqual(full.decision, "DENY")
        self.assertFalse((self.home / "state.json").exists())

    def test_corrupt_state_is_sealed(self) -> None:
        (self.home / "state.json").write_text("{", encoding="utf-8")
        self.assertEqual(self.gate.discover().code, "egress_sealed")

    def test_open_record_without_receipt_is_not_open(self) -> None:
        (self.home / "state.json").write_text(
            json.dumps({"protocol": PROTOCOL, "state": "open", "seal": "human"}),
            encoding="utf-8",
        )
        self.assertEqual(self.gate.admit(Segment(0)).code, "egress_sealed")

    def test_open_requires_configured_seal(self) -> None:
        self.assertEqual(self.gate.open("anything").code, "seal_unconfigured")
        self.assertEqual(self.gate.open("  ").code, "human_seal_required")

    def test_mismatch_stays_sealed(self) -> None:
        self.assertTrue(self.gate.init_seal(SEAL).ok)
        denied = self.gate.open("other-seal")
        self.assertEqual(denied.code, "seal_mismatch")
        self.assertEqual(self.gate.discover().code, "egress_sealed")

    def test_human_seal_opens_and_close_is_automatic(self) -> None:
        self.gate.init_seal(SEAL)
        opened = self.gate.open(SEAL)
        self.assertEqual(opened.decision, "ALLOW")
        self.assertEqual(self.gate.discover().decision, "ALLOW")
        self.assertEqual(self.gate.admit(Segment(0)).decision, "ALLOW")
        self.assertEqual(self.gate.admit(Segment(4)).decision, "ALLOW")
        self.assertEqual(self.gate.check("remote_service_discovery").decision, "ALLOW")
        closed = self.gate.close()
        self.assertEqual(closed.decision, "SHUT")
        self.assertEqual(self.gate.admit(Segment(0)).code, "egress_sealed")
        self.assertEqual(self.gate.check("rsd").code, "egress_sealed")

    def test_secret_is_not_stored(self) -> None:
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertNotIn(SEAL, self._files())

    def test_negative_length_is_deny_when_open(self) -> None:
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertEqual(self.gate.admit(Segment(-1)).code, "malformed_segment")

    def test_other_actions_abstain(self) -> None:
        body = self.gate.check("read")
        self.assertEqual(body.decision, "ABSTAIN")
        self.assertEqual(body.code, "outside_gate")

    def test_failed_check_is_deny(self) -> None:
        def boom() -> None:
            raise RuntimeError("broken")

        self.gate._lock = boom  # type: ignore[method-assign]
        denied = self.gate.discover()
        self.assertEqual(denied.decision, "DENY")
        self.assertEqual(denied.code, "egress_error")
        self.assertEqual(denied.state, "sealed")

    def test_unrecorded_open_does_not_stick(self) -> None:
        self.gate.init_seal(SEAL)
        (self.home / "receipts.jsonl").unlink()
        (self.home / "receipts.jsonl").mkdir()
        denied = self.gate.open(SEAL)
        self.assertEqual(denied.code, "unrecorded")
        self.assertFalse((self.home / "state.json").exists())
        self.assertEqual(self.gate.discover().code, "egress_sealed")

    def test_witness_unknown_when_nothing_declared(self) -> None:
        body = judge([])
        self.assertEqual(body["state"], "unknown")
        self.assertNotEqual(body["state"], "sealed")

    def test_witness_sealed_only_when_down_blocked_and_still(self) -> None:
        quiet = judge([Channel("a", up=False, blocked=True, bytes_in=0, bytes_out=0)])
        self.assertEqual(quiet["state"], "sealed")
        self.assertEqual(quiet["rsd_presence"], "absent")
        up = judge([Channel("a", up=True, blocked=True)])
        self.assertEqual(up["state"], "leaking")
        self.assertEqual(up["rsd_presence"], "present")
        moved = judge([Channel("a", up=False, blocked=True, bytes_in=1, bytes_out=0)])
        self.assertEqual(moved["state"], "leaking")
        open_pipe = judge([Channel("a", up=False, blocked=False)])
        self.assertEqual(open_pipe["state"], "leaking")

    def test_reseal_calls_enforcer_only_on_a_leak(self) -> None:
        called: list[list[str]] = []

        def enforcer(names: list[str]) -> None:
            called.append(names)

        quiet = [Channel("a", up=False, blocked=True)]
        self.assertEqual(self.gate.reseal(quiet, enforcer).code, "already_sealed")
        self.assertEqual(called, [])
        leaking = [Channel("a", up=True, blocked=False, bytes_out=2)]
        body = self.gate.reseal(leaking, enforcer)
        self.assertEqual(body.decision, "SHUT")
        self.assertEqual(called, [["a"]])

    def test_reseal_while_open_does_not_close(self) -> None:
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        body = self.gate.reseal([Channel("a", up=True, blocked=False)], lambda _names: None)
        self.assertEqual(body.code, "already_open")
        self.assertEqual(self.gate.discover().decision, "ALLOW")

    def test_init_seal_refused_while_open(self) -> None:
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertEqual(self.gate.init_seal("next-seal").code, "seal_exists_use_rotate")

    def test_second_seal_needs_rotate(self):
        self.gate.init_seal(SEAL)
        self.assertEqual(self.gate.init_seal("next-seal").code, "seal_exists_use_rotate")

    def test_rotate_requires_current_seal(self):
        self.gate.init_seal(SEAL)
        self.assertEqual(self.gate.rotate("wrong-seal", "new-seal").code, "seal_mismatch")
        self.assertEqual(self.gate.rotate(SEAL, "new-seal").code, "seal_rotated")

    def test_rotate_while_open_returns_seal_while_open(self):
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertEqual(self.gate.rotate(SEAL, "new-seal").code, "seal_while_open")

    def test_forged_open_without_chain_stays_sealed(self):
        self.gate.init_seal(SEAL)
        try:
            (self.home / "receipts.jsonl").unlink()
        except FileNotFoundError:
            pass
        forged_receipts = [
            {"protocol": PROTOCOL, "gate": GATE, "seq": 0, "prev": "0"*64, "verb": "seal", "mood": "SET", "code": "seal_configured", "when": "2023-01-01T00:00:00Z"},
            {"protocol": PROTOCOL, "gate": GATE, "seq": 1, "prev": "invalid_hash", "verb": "open", "mood": "ALLOW", "code": "seal_opened", "when": "2023-01-01T00:00:00Z"}
        ]
        (self.home / "receipts.jsonl").write_text("\n".join(json.dumps(r) for r in forged_receipts), encoding="utf-8")
        # Manually set state.json to open
        state_data = {
            "protocol": PROTOCOL,
            "state": "open",
            "seal": "human",
            "expires": int(time.time()) + 3600
        }
        with open(self.home / "state.json", "w") as f:
            json.dump(state_data, f)
        self.assertEqual(self.gate.discover().code, "egress_sealed")
        # Same forgery as complete lines (trailing newline), so the broken chain itself is what denies.
        (self.home / "receipts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in forged_receipts), encoding="utf-8")
        self.assertEqual(self.gate.admit(Segment(1)).decision, "DENY")
        self.assertEqual(self.gate.discover().decision, "DENY")

    def test_close_takes_effect_when_receipts_unwritable(self):
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertEqual(self.gate.discover().decision, "ALLOW")
        (self.home / "receipts.jsonl").chmod(0o400)
        try:
            closed = self.gate.close()
            self.assertEqual(closed.decision, "SHUT")
            self.assertEqual(closed.code, "sealed_unrecorded")
            self.assertEqual(self.gate.discover().code, "egress_sealed")
        finally:
            (self.home / "receipts.jsonl").chmod(0o600)

    def test_abstain_is_not_ok(self):
        body = self.gate.check("read")
        self.assertEqual(body.decision, "ABSTAIN")
        self.assertFalse(body.allowed)
        self.assertFalse(body.ok)

    def test_witness_rejects_strings_and_negatives(self):
        bad_channel = Channel("a", up="yes", blocked=True)
        self.assertEqual(judge([bad_channel])["state"], "unknown")
        bad_channel = Channel("a", up=True, blocked="yes")
        self.assertEqual(judge([bad_channel])["state"], "unknown")
        bad_channel = Channel("a", up=True, blocked=True, bytes_in=-1)
        self.assertEqual(judge([bad_channel])["state"], "unknown")

    def test_torn_tail_does_not_brick(self):
        (self.home / "receipts.jsonl").write_text('{"seq":0,"prev":"0"*64}', encoding="utf-8")
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.assertEqual(self.gate.discover().decision, "ALLOW")

    def test_open_expires(self):
        self.gate.init_seal(SEAL)
        self.gate.open(SEAL)
        self.gate._clock = lambda: time.time() + 3601
        self.assertEqual(self.gate.discover().code, "egress_sealed")

    # Second-reader review, 2026-09-26: each of these read as "sealed" or crashed before the fix.
    def test_witness_iterator_is_not_sealed(self):
        leaking = Channel("eth0", True, False, 5, 5)
        self.assertEqual(judge(iter([leaking]))["state"], "leaking")
        self.assertEqual(judge(c for c in [leaking])["state"], "leaking")

    def test_reseal_iterator_calls_enforcer(self):
        called = []
        body = self.gate.reseal(iter([Channel("a", True, False, 0, 2)]), lambda names: called.append(names))
        self.assertEqual((body.decision, called), ("SHUT", [["a"]]))

    def test_cli_witness_does_not_coerce_bad_values(self):
        import subprocess, sys
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent / "src"))
        for row in ('{"name":"eth0","up":false,"blocked":"false","bytes_in":0,"bytes_out":0}',
                    '{"name":"eth0","up":false,"blocked":true,"bytes_in":0.9,"bytes_out":0}',
                    '{"name":"eth0","up":false,"blocked":true,"bytes_in":0,"bytes_out":-0.5}',
                    '{"name":"eth0","up":false,"blocked":true,"bytes_in":1e400,"bytes_out":0}'):
            r = subprocess.run([sys.executable, "-m", "headgate_egress", "witness"], input="[" + row + "]",
                               capture_output=True, text=True, env=env)
            self.assertNotEqual(r.returncode, 0, row)
            self.assertNotIn('"state": "sealed"', r.stdout, row)

    def test_enforcer_failure_is_reported_not_crashed(self):
        def boom(names):
            raise RuntimeError("enforcer down")
        body = self.gate.reseal([Channel("a", True, False, 0, 2)], boom)
        self.assertEqual((body.decision, body.code), ("DENY", "enforcer_failed"))
        receipts = (self.home / "receipts.jsonl").read_text() if (self.home / "receipts.jsonl").exists() else ""
        self.assertNotIn('"code": "egress_sealed"', receipts)

    def test_extra_cannot_overwrite_decision_fields(self):
        body = self.gate.reseal([Channel("a", True, False, 0, 2)], lambda names: None).as_dict()
        self.assertEqual(body["state"], "sealed")
        self.assertEqual(body["observed"], "leaking")
        self.assertTrue(body["ok"])

    def test_discovery_variants_are_denied(self):
        for action in ("RSD", "rsd ", "Discover", "remote-service-discovery", " discover"):
            self.assertEqual(self.gate.check(action).decision, "DENY", action)

    def test_ttl_is_capped(self):
        self.gate.init_seal(SEAL)
        self.assertEqual(self.gate.open(SEAL, ttl_seconds=10 ** 11).code, "ttl_too_long")

if __name__ == "__main__":
    unittest.main()