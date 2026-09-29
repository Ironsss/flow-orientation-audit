"""
Feature attribution audit protocol for correlated and imbalanced datasets.

Standard feature-importance methods (permutation importance, Gini/gain, SHAP)
answer the question "how much does *this fitted model* rely on feature f?".
That is not the question a practitioner usually means. The intended question
is normally "does feature f carry information that the rest of the feature
set does not already carry?" -- a property of the data, not of one fit.

Those two questions diverge sharply when features are correlated, and the
divergence is not subtle. Measured on synthetic data with known ground truth
(see docs/protocolo/): adding three near-duplicate copies of the single most
informative feature drops its permutation importance from 0.6978 to 0.0003
and its rank from 1st to 12th, while the underlying data-generating process
is unchanged.

Whether summing within the correlated group repairs that depends on which
method produced the numbers, and the two behave oppositely. Group sums with
three copies present, against the same group measured without copies, mean
of five seeds:

    method                  no copies    3 copies    retained
    permutation importance    0.67772     0.00551         0.8%
    SHAP (TreeExplainer)      0.07619     0.08822         116%

Permutation importance measures the marginal effect of destroying one
column, and with an identical copy still in the matrix that effect is zero --
so credit is destroyed rather than moved, every member scores ~0, and the sum
of zeros is zero. SHAP allocates credit subject to an efficiency constraint,
so credit is *divided* among the correlated members but not lost, and the sum
survives. Practically: group-summing is a valid cheap repair for SHAP and an
invalid one for permutation importance.

The repair that works for both is leave-group-out ablation: drop the whole
correlated group and *refit*, then measure the loss in a metric appropriate
to the label distribution. This module implements that, plus the independence
probe described below.

Three primitives:

1. `correlation_groups`   -- cluster features so that mutually redundant ones
                             are audited together rather than against each other.
2. `leave_group_out`      -- drop a group, refit, measure the drop. Model- and
                             metric-agnostic.
3. `independence_probe`   -- a falsifiable, preregistered test: construct two
                             inputs that every existing feature scores
                             identically but that differ in the property the
                             candidate feature claims to measure, and require
                             the candidate to separate them.

The probe originated in this repository's spectral-asymmetry investigation
(docs/matematicas/03-asimetria-espectral.md), where it rejected three
mathematically correct formulations that turned out to be redundant with
features already present. Its value is that it is a *design-time* test: it
does not depend on a fitted model, a sample size, or a class balance.

Scope: everything here was developed and measured for this project's own
feature set, plus synthetic data built to mirror it. It is not claimed to
generalize to other domains or dataset shapes; nothing outside this case has
been tested.

Its cost is that it is not automatic. Constructing the falsifying pair
requires knowing what property the feature is supposed to capture. The probe
converts a statistical question into a design question -- more reliable, but
it asks more of the analyst.
"""

from src.audit.ablation import GroupImportance, correlation_groups, leave_group_out
from src.audit.canonical import (
    CanonicalWindowing,
    anchor_shift_seconds,
    build_canonical_windowing,
    canonical_window_features,
    map_to_canonical_window,
)
from src.audit.probe import ProbeResult, independence_probe, probe_suite

__all__ = [
    "CanonicalWindowing",
    "GroupImportance",
    "ProbeResult",
    "anchor_shift_seconds",
    "build_canonical_windowing",
    "canonical_window_features",
    "correlation_groups",
    "independence_probe",
    "leave_group_out",
    "map_to_canonical_window",
    "probe_suite",
]
