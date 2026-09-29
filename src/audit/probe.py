"""The independence probe: a preregistered, falsifiable redundancy test."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one independence probe.

    Attributes
    ----------
    passed : bool
        True only if every existing feature scored the two inputs as
        equivalent *and* the candidate separated them. Both halves are
        required: a probe where the existing features already disagree proves
        nothing about the candidate, because the pair was not a valid control.
    candidate_values : tuple[float, float]
        The candidate's value on each input.
    candidate_separation : float
        ``abs`` difference of the two candidate values.
    controls_held : bool
        Whether every existing feature scored the pair as equivalent. When
        False, the probe is void rather than failed -- rebuild the pair.
    violating_controls : tuple[str, ...]
        Existing features that separated the pair, i.e. why the control broke.
    reason : str
        Human-readable verdict, suitable for pasting into a lab notebook.
    """

    passed: bool
    candidate_values: tuple[float, float]
    candidate_separation: float
    controls_held: bool
    violating_controls: tuple[str, ...]
    reason: str


def independence_probe(
    candidate: Callable[[Any], float],
    existing: Mapping[str, Callable[[Any], float]],
    pair: tuple[Any, Any],
    *,
    min_separation: float,
    control_tolerance: float = 1e-9,
    candidate_name: str = "candidate",
) -> ProbeResult:
    """Test whether a candidate feature carries information the existing set lacks.

    The protocol, which only means anything if executed in this order:

    1. Pick the property ``P`` the candidate claims to measure.
    2. Construct two inputs that every existing feature scores *identically*
       but that differ in ``P``.
    3. Declare ``min_separation`` -- how far apart the candidate must place
       them to count -- **before** running this function.
    4. Run. If the candidate does not separate them, it is redundant with the
       existing set, however sound its derivation.

    Step 3 is the part that is normally skipped and the part that does the
    work. A threshold chosen after seeing the values is not a test.

    This is a design-time check, not a statistical one. It does not fit a
    model, does not consume samples, and has no variance, so unlike
    permutation importance or SHAP it does not degrade when the positive class
    is rare -- which is exactly the regime where those methods are least
    trustworthy. What it asks in exchange is that you be able to state what
    ``P`` is and build a pair that isolates it.

    A pass is evidence of non-redundancy on *this* pair, not proof of general
    usefulness: a feature can separate the constructed pair and still be
    useless on real data. A failure is the stronger signal, and it is
    conclusive for the property tested.

    Parameters
    ----------
    candidate : callable mapping an input to a scalar.
    existing : mapping of name -> callable for every feature already in the set.
        Pass all of them. Omitting one is how a redundant feature survives.
    pair : the two constructed inputs ``(a, b)``.
    min_separation : required ``abs(candidate(a) - candidate(b))``. Declare
        first. Must be positive.
    control_tolerance : how close two existing-feature values must be to count
        as equivalent. Defaults to 1e-9; raise it for features with genuine
        floating-point noise, but raising it far enough to rescue a broken
        pair is self-deception.
    candidate_name : name used in ``reason``.

    Returns
    -------
    ProbeResult

    Examples
    --------
    The probe that retired this project's spectral component: a DDoS-like
    star and a directed cycle both have directional asymmetry exactly 1.0, so
    they are a valid control pair for any feature claiming to measure global
    structure beyond edge reciprocity. Three formulations that were
    mathematically correct scored them identically and were rejected.
    """
    if min_separation <= 0:
        raise ValueError(
            "min_separation must be positive and declared before running; "
            f"got {min_separation}"
        )
    if control_tolerance < 0:
        raise ValueError(f"control_tolerance must be non-negative, got {control_tolerance}")

    a, b = pair

    violating: list[str] = []
    for name, fn in existing.items():
        va, vb = float(fn(a)), float(fn(b))
        if not (np.isfinite(va) and np.isfinite(vb)):
            violating.append(name)
            continue
        if abs(va - vb) > control_tolerance:
            violating.append(name)

    ca, cb = float(candidate(a)), float(candidate(b))
    separation = abs(ca - cb)
    controls_held = not violating

    if not controls_held:
        reason = (
            f"VOID: the pair is not a valid control. These existing features already "
            f"separate it: {', '.join(sorted(violating))}. Nothing can be concluded about "
            f"{candidate_name}; rebuild the pair so every existing feature scores it equally."
        )
        return ProbeResult(False, (ca, cb), separation, False, tuple(sorted(violating)), reason)

    if not np.isfinite(separation):
        reason = f"FAIL: {candidate_name} returned a non-finite value ({ca}, {cb})."
        return ProbeResult(False, (ca, cb), separation, True, (), reason)

    if separation >= min_separation:
        reason = (
            f"PASS: {candidate_name} separates the pair by {separation:.6g} "
            f"(required {min_separation:.6g}) while all {len(existing)} existing features "
            f"score it identically. Non-redundant for the property tested."
        )
        return ProbeResult(True, (ca, cb), separation, True, (), reason)

    reason = (
        f"FAIL: {candidate_name} separates the pair by only {separation:.6g} "
        f"(required {min_separation:.6g}) although the two inputs differ in the property "
        f"it claims to measure. It is redundant with the existing feature set here, "
        f"regardless of how it was derived."
    )
    return ProbeResult(False, (ca, cb), separation, True, (), reason)


def probe_suite(
    candidate: Callable[[Any], float],
    existing: Mapping[str, Callable[[Any], float]],
    pairs: Sequence[tuple[Any, Any]],
    *,
    min_separation: float,
    control_tolerance: float = 1e-9,
    candidate_name: str = "candidate",
) -> list[ProbeResult]:
    """Run `independence_probe` over several constructed pairs.

    A candidate should be probed against every property it claims, not just
    the one most likely to pass. Void results (broken control pairs) are
    returned rather than dropped, so a suite that looks like it passed cannot
    be hiding pairs that never tested anything.
    """
    return [
        independence_probe(
            candidate,
            existing,
            pair,
            min_separation=min_separation,
            control_tolerance=control_tolerance,
            candidate_name=candidate_name,
        )
        for pair in pairs
    ]
