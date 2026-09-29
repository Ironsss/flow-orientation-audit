"""Information tiers: what a deployment actually has, ordered by cost.

This is the organizing principle of the project after the operational
re-framing (docs/metodologia/REPLANTEO-OPERACIONAL.md). The relevant question
stopped being "which features score best on CICIDS" and became "which
representation survives the information a real deployment has".

CICIDS features presuppose FULL: CICFlowMeter reconstructs every flow packet by
packet to produce `bwd_pkt_len_std` and `fwd_iat_mean`. A production router does
not do that at line rate. It exports NetFlow/IPFIX -- typically sampled, often
without per-direction byte counts -- which lands somewhere between TUPLES and
DIRECTIONAL depending on configuration.

So a feature's tier is not a taxonomy detail. It is a claim about whether the
feature can exist in the setting the project cares about, and the whole point of
declaring it in code is that an experiment can then ask for "everything
available at tier <= T" and get an answer that means something operationally.

    TUPLES       (src, dst) per flow.
                 The first thing any router exports; available immediately,
                 before a flow completes. Topology lives here.

    COUNTS       + flow and packet counts, no direction split.
                 Common in aggregated NetFlow.

    DIRECTIONAL  + per-direction byte and packet counts.
                 Where per-flow asymmetry becomes computable at all. Requires
                 the exporter to keep both halves of a conversation associated,
                 which sampling frequently breaks.

    FULL         + inter-arrival statistics, packet-length distributions.
                 What CICIDS ships and what almost no deployment has.

Ordering matters and is the only thing the enum guarantees: a feature at tier T
is computable whenever the available information is at tier T or richer.
"""

from __future__ import annotations

from enum import IntEnum


class InfoTier(IntEnum):
    """Minimum information a feature needs in order to exist.

    IntEnum rather than Enum so that ``tier <= InfoTier.DIRECTIONAL`` is a
    meaningful filter -- that comparison is how experiments select a feature
    set, so the ordering is load-bearing rather than cosmetic.
    """

    TUPLES = 1
    COUNTS = 2
    DIRECTIONAL = 3
    FULL = 4

    @property
    def description(self) -> str:
        return {
            InfoTier.TUPLES: "(src, dst) only -- always exported, available before a flow ends",
            InfoTier.COUNTS: "+ flow/packet counts, no direction split",
            InfoTier.DIRECTIONAL: "+ per-direction byte counts -- needed for per-flow asymmetry",
            InfoTier.FULL: "+ IAT and packet-length statistics -- what CICIDS ships",
        }[self]


#: Columns each tier assumes are present in an ingested flow frame. Used by
#: `src.restriction` to enforce a tier by dropping what a tier cannot see, so
#: that a restricted run genuinely cannot cheat by reading a richer column.
TIER_COLUMNS: dict[InfoTier, tuple[str, ...]] = {
    InfoTier.TUPLES: ("timestamp", "src_ip", "dst_ip"),
    InfoTier.COUNTS: ("timestamp", "src_ip", "dst_ip", "tot_fwd_pkts", "tot_bwd_pkts"),
    InfoTier.DIRECTIONAL: (
        "timestamp", "src_ip", "dst_ip",
        "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    ),
    InfoTier.FULL: (),  # everything the loader produced
}
