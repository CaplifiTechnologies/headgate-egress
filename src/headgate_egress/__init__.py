"""Egress Headgate reference. Resting state passes nothing."""

from headgate_egress.gate import (
    GATE,
    PROTOCOL,
    Channel,
    Decision,
    Gate,
    Segment,
    judge,
    resting,
)

__all__ = [
    "GATE",
    "PROTOCOL",
    "Channel",
    "Decision",
    "Gate",
    "Segment",
    "judge",
    "resting",
]
