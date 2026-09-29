"""Feature extraction organized by the information a deployment actually has.

The project's organizing principle after the operational re-framing
(docs/metodologia/REPLANTEO-OPERACIONAL.md): a feature's value is inseparable
from whether it can be computed at all in the setting that matters. CICIDS
ships features that presuppose full packet reconstruction; a router exports
addresses and little else.

    from src.features import InfoTier, features_at_tier, window_features

    window_features(df, tier=InfoTier.TUPLES)       # topology only
    window_features(df, tier=InfoTier.DIRECTIONAL)  # + per-flow asymmetry
"""

from src.features.extractors import (
    FEATURE_TIERS,
    PERFLOW_FEATURES,
    SIZE_FEATURES,
    TOPOLOGY_FEATURES,
    features_at_tier,
    perflow_features,
    size_features,
    topology_features,
)
from src.features.tiers import TIER_COLUMNS, InfoTier
from src.features.windows import window_features

__all__ = [
    "FEATURE_TIERS",
    "PERFLOW_FEATURES",
    "SIZE_FEATURES",
    "TIER_COLUMNS",
    "TOPOLOGY_FEATURES",
    "InfoTier",
    "features_at_tier",
    "perflow_features",
    "size_features",
    "topology_features",
    "window_features",
]
