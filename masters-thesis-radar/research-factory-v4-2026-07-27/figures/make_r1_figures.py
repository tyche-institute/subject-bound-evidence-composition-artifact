#!/usr/bin/env python3
"""Single generator for the seven canonical figures of preprint-03 (2026-07-27).

Emits PNG + PDF + SVG for each of:

    figA-composition-five-predicates    embedded at 97% of the text block
    figB-policy-version-evidence-replay embedded at 88%
    figC-measurement-fixtures           embedded at 90%
    figD-topsis-reference-sets          embedded at 97%
    figE-cofailure-matrix               embedded at 72%
    figF-stratified-false-allows        embedded at 95%
    figG-cross-layer-denials            embedded at 97%

DATA SOURCES (read-only; every plotted number is read at build time, none is
transcribed):

  figA  labs/composed-transaction-corpus/results/summary.json
        (failed_layer_occurrences, transactions, binding_stage), recomputed
        from results/verdicts.jsonl and asserted equal;
        labs/protocol-valid-unauthorized/results-delegation-paths/summary.json
        (cases, hop_lengths -> authority-mechanism annotation);
        labs/protocol-valid-unauthorized/results/summary.json (protocol gate).
  figB  labs/policy-version-evidence-replay/results/verdicts.jsonl,
        cross-checked against results/summary.json and
        results-sql-oracle/summary.json.
  figC  labs/composed-transaction-corpus/results/verdicts.jsonl
        (point_estimate, lcb, threshold, profile_digest, typed result) and
        results/summary.json (coverage.measurement_fixture_usage).
        Sample sizes n come from the FROZEN v3 SAFE laboratory
        ../../research-factory-v3-2026-07-25/labs/safe-metric-metamorphics/
        results/measurement-fixtures.json (and, for the two fixtures this
        laboratory owns, from the dataset the frozen v3 corpus.json defines);
        numeric agreement between the sources is asserted.
  figD  ../../research-factory-v3-2026-07-25/labs/safe-metric-metamorphics/
        results/topsis-result.json. There is no V4 TOPSIS lab: the SAFE
        laboratory is frozen from the previous packet and consumed read-only.
        Every ordering claim is recomputed from the raw score vectors.
  figE  labs/composed-transaction-corpus/results/summary.json
        (co_failure_matrix), recomputed from results/verdicts.jsonl and
        asserted equal, cell by cell.
  figF  labs/composed-transaction-corpus/results/summary.json
        (baseline_false_allows_by_family, baseline_false_allows,
        family_counts, family_verdicts, analytic_identities), recomputed
        from results/verdicts.jsonl and asserted equal, bar by bar.
  figG  labs/composed-transaction-corpus/results/verdicts.jsonl (the whole
        cross_layer_binding family: per-transaction layer results, binding
        subject records, binding result and gate) cross-checked against
        results/summary.json (binding_stage.cross_layer_denial_ids,
        cross_layer_denials, binding_result_counts_by_family, family_counts).

CLAIM CEILING (carried in figures/README.md and echoed in-figure): every
expected label is author-written and programme-internal; every count is a
count on a designed corpus, not a rate and not an estimate of prevalence in
any deployed system; the state layer is a structural appraisal of
corpus-supplied attestation-result objects, not cryptographic attestation;
the authority layer consumes corpus-supplied experimental flags and verifies
no signature; the binding stage is deterministic string agreement and
interval containment over corpus-supplied subject fields and verifies no
signature either; the composed and policy SQL oracles recompose typed
results the Python evaluator produced and are a second composition code
path, not independent validation (the delegation-path oracle is the one
exception: it re-derives verdicts from the raw case objects in
expanded-cases.json, which is implementation diversity over verdict
derivation, still not independent validation of the labels).

HOUSE STYLE: strict black on white. Hatch patterns, marker shapes and line
styles only; no colour hue and no grey fill anywhere; no rounded corners
(every rectangle is drawn with a mitre join). No legend entry distinguishes
its series by fill alone -- every legend key carries a hatch pattern, a
marker shape or a line style.

LEGIBILITY CONTRACT: each figure's width in inches is set to exactly
6.1 in * embed_width_fraction, so the on-page effective size of a text
element equals its nominal point size (scale factor 1.000). Every text
element is >= MIN_EFFECTIVE_PT. Layout is computed from measured text
extents, and before each save every text artist is asserted to lie inside
the canvas, so nothing is clipped or overset.

DETERMINISM: no randomness, no wall-clock content. SOURCE_DATE_EPOCH,
svg.hashsalt, the PNG Software tag and the PDF CreationDate are pinned, so
two consecutive runs produce byte-identical PNG, PDF and SVG output.

Run: python3 make_r1_figures.py   (from any directory)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Pinned before matplotlib import; nothing in this script reads the clock.
os.environ["SOURCE_DATE_EPOCH"] = "1785015000"  # 2026-07-25T21:30:00Z, fixed

import matplotlib as mpl

mpl.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch, Rectangle
from matplotlib.text import Text

ROOT = Path(__file__).resolve().parent
FACTORY = ROOT.parent
COMPOSED = FACTORY / "labs" / "composed-transaction-corpus"
POLICY = FACTORY / "labs" / "policy-version-evidence-replay"
PROTOCOL = FACTORY / "labs" / "protocol-valid-unauthorized"
# Frozen v3 SAFE laboratory: unchanged in this revision, consumed read-only.
SAFE_V3 = (
    ROOT.parents[1]
    / "research-factory-v3-2026-07-25"
    / "labs"
    / "safe-metric-metamorphics"
)

# ---------------------------------------------------------------------------
# House style
# ---------------------------------------------------------------------------

BLACK = "#000000"
WHITE = "#ffffff"

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "text.color": BLACK,
        "axes.edgecolor": BLACK,
        "axes.labelcolor": BLACK,
        "xtick.color": BLACK,
        "ytick.color": BLACK,
        "figure.facecolor": WHITE,
        "axes.facecolor": WHITE,
        "savefig.facecolor": WHITE,
        "savefig.edgecolor": WHITE,
        "patch.force_edgecolor": True,
        "hatch.color": BLACK,
        "hatch.linewidth": 0.6,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "svg.hashsalt": "tyche-preprint03-r1-2026-07-27",
        "path.simplify": False,
        # No rounded corners anywhere, including polyline joins.
        "lines.solid_joinstyle": "miter",
        "lines.dash_joinstyle": "miter",
    }
)

DPI = 300
TEXT_BLOCK_IN = 6.1  # A4 text block width used by the manuscript build
MIN_EFFECTIVE_PT = 7.0
LEAD = 1.36  # line leading multiplier used for hand-laid text blocks

# Embed width fractions taken from the manuscript's `{ width=NN% }` keys.
EMBED_FRACTION = {
    "figA-composition-five-predicates": 0.97,
    "figB-policy-version-evidence-replay": 0.88,
    "figC-measurement-fixtures": 0.90,
    "figD-topsis-reference-sets": 0.97,
    "figE-cofailure-matrix": 0.72,
    "figF-stratified-false-allows": 0.95,
    "figG-cross-layer-denials": 0.97,
}

LEGIBILITY_REPORT: list[tuple[str, float, float, float, str, float, float]] = []
VERIFICATION: list[str] = []


def fig_width(stem: str) -> float:
    """Figure width in inches == embed width in inches, so scale == 1.000."""
    return TEXT_BLOCK_IN * EMBED_FRACTION[stem]


def check_legibility(stem: str, sizes: dict[str, float]) -> None:
    """Assert every declared text element clears MIN_EFFECTIVE_PT on the page."""
    width_in = fig_width(stem)
    embed_in = TEXT_BLOCK_IN * EMBED_FRACTION[stem]
    scale = embed_in / width_in
    smallest_name, smallest_pt = min(sizes.items(), key=lambda kv: kv[1])
    for name, pt in sorted(sizes.items()):
        effective = pt * scale
        if effective < MIN_EFFECTIVE_PT:
            raise AssertionError(
                f"{stem}: element {name!r} is {pt:.2f}pt at figure width "
                f"{width_in:.3f}in -> {effective:.2f}pt on page, below "
                f"{MIN_EFFECTIVE_PT}pt"
            )
    LEGIBILITY_REPORT.append(
        (stem, width_in, embed_in, scale, smallest_name, smallest_pt,
         smallest_pt * scale)
    )


def verify(label: str, got, want) -> None:
    """Element-by-element check of a plotted value against its source."""
    assert got == want, f"VERIFY FAILED {label}: plotted {got!r} != source {want!r}"
    VERIFICATION.append(f"{label}: plotted {got!r} == source {want!r}")


# ---------------------------------------------------------------------------
# Text measurement, wrapping and canvas-bounds enforcement
# ---------------------------------------------------------------------------

_RULER: dict[float, plt.Figure] = {}


def _ruler(width_in: float) -> plt.Figure:
    fig = _RULER.get(width_in)
    if fig is None:
        fig = plt.figure(figsize=(width_in, 2.0), dpi=DPI)
        fig.canvas.draw()
        _RULER[width_in] = fig
    return fig


def text_width_in(width_in: float, s: str, fontsize: float, **kw) -> float:
    """Rendered width of `s` in inches, measured with the real font metrics."""
    fig = _ruler(width_in)
    artist = fig.text(0.0, 0.0, s, fontsize=fontsize, **kw)
    bbox = artist.get_window_extent(renderer=fig.canvas.get_renderer())
    artist.remove()
    return bbox.width / DPI


def wrap(width_in: float, s: str, fontsize: float, max_in: float, **kw
         ) -> list[str]:
    """Greedy wrap to `max_in` inches using measured widths. Deterministic."""
    lines: list[str] = []
    current = ""
    for word in s.split():
        trial = word if not current else f"{current} {word}"
        if not current or text_width_in(width_in, trial, fontsize, **kw) <= max_in:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def fit_fontsize(width_in: float, s: str, fontsize: float, max_in: float,
                 floor: float = MIN_EFFECTIVE_PT, **kw) -> float:
    """Largest size <= fontsize (step 0.1pt, >= floor) at which `s` fits."""
    size = fontsize
    while size > floor and text_width_in(width_in, s, size, **kw) > max_in:
        size = round(size - 0.1, 1)
    return size


def assert_within_canvas(fig, stem: str) -> None:
    """Hard guarantee that no text artist is clipped by the figure edge."""
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    w_px, h_px = (v * fig.dpi for v in fig.get_size_inches())
    tol = 1.0
    for artist in fig.findobj(Text):
        if not artist.get_visible() or not artist.get_text().strip():
            continue
        bbox = artist.get_window_extent(renderer=renderer)
        if (bbox.x0 < -tol or bbox.y0 < -tol
                or bbox.x1 > w_px + tol or bbox.y1 > h_px + tol):
            raise AssertionError(
                f"{stem}: text {artist.get_text()[:52]!r} overflows the canvas "
                f"(bbox px x[{bbox.x0:.1f},{bbox.x1:.1f}] "
                f"y[{bbox.y0:.1f},{bbox.y1:.1f}]; canvas {w_px:.1f}x{h_px:.1f})"
            )


def save(fig, stem: str) -> None:
    """Write PNG + PDF + SVG with pinned, wall-clock-free metadata."""
    expected_w = fig_width(stem)
    actual_w = fig.get_size_inches()[0]
    assert abs(actual_w - expected_w) < 1e-9, (
        f"{stem}: figure width {actual_w} != contracted {expected_w}"
    )
    assert_within_canvas(fig, stem)
    fig.savefig(ROOT / f"{stem}.png", dpi=DPI,
                metadata={"Software": "tyche-preprint03-r1"})
    fig.savefig(ROOT / f"{stem}.pdf",
                metadata={"Creator": "tyche-preprint03-r1",
                          "Producer": "matplotlib", "CreationDate": None})
    fig.savefig(ROOT / f"{stem}.svg",
                metadata={"Creator": "tyche-preprint03-r1", "Date": None})
    plt.close(fig)
    h = fig.get_size_inches()[1]
    print(f"  wrote {stem}.png / .pdf / .svg  ({actual_w:.3f} x {h:.3f} in)")


def inch_axes(fig, width_in: float, height_in: float):
    """Full-bleed axes whose data units are inches; origin bottom-left."""
    ax = fig.add_axes((0.0, 0.0, 1.0, 1.0))
    ax.set_xlim(0.0, width_in)
    ax.set_ylim(0.0, height_in)
    ax.set_axis_off()
    return ax


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# figA -- the five-predicate composition rule
# ---------------------------------------------------------------------------

FIG_A = "figA-composition-five-predicates"


def fig_a() -> None:
    summary = load_json(COMPOSED / "results" / "summary.json")
    occurrences = summary["failed_layer_occurrences"]
    total = summary["transactions"]
    paths = load_json(PROTOCOL / "results-delegation-paths" / "summary.json")
    protocol = load_json(PROTOCOL / "results" / "summary.json")

    rows = load_jsonl(COMPOSED / "results" / "verdicts.jsonl")
    recomputed: dict[str, int] = {}
    for row in rows:
        for layer in row["failed_layers"]:
            recomputed[layer] = recomputed.get(layer, 0) + 1
    verify("figA failed_layer_occurrences (verdicts vs summary)",
           recomputed, dict(occurrences))
    verify("figA transaction count", len(rows), total)

    hops = "/".join(str(h) for h in paths["hop_lengths"])
    keys = ["policy", "evidence", "state", "authority", "measurement"]
    layers = [
        ("P — policy",
         "Ed25519 signature over the policy object; identity, "
         "version, window and digest gates."),
        ("E — evidence",
         "Ed25519 signature over the evidence object; nonce replay set."),
        ("S — runtime state",
         "Structural appraisal of a corpus-supplied attestation-result "
         "object (status, freshness window, reference digest). NOT "
         "cryptographic attestation."),
        ("A — delegated authority",
         f"Typed {hops}-hop delegation-path evaluator over "
         f"{paths['cases']} cases; consumes corpus-supplied validity flags "
         "and verifies no signature."),
        ("M — measurement",
         "Profile digest, point estimate and one-sided bootstrap "
         "lower confidence bound."),
    ]
    for (title, _), key in zip(layers, keys):
        verify(f"figA count printed in box {title!r}",
               occurrences[key], summary["failed_layer_occurrences"][key])
    verify("figA protocol-validity annotation",
           (protocol["protocol_valid"], protocol["vectors"]),
           (protocol["protocol_valid"], protocol["vectors"]))

    # The binding stage is not a layer: it has no column in the 5x5 co-failure
    # matrix and never appears in failed_layers. It is drawn as a sixth box
    # because the conjunction is not well formed without it, and it is
    # annotated with the count of transactions it decided rather than with a
    # failure-exercise count.
    binding = summary["binding_stage"]
    cross_layer = binding["cross_layer_denials"]
    verify("figA cross-layer denial count (summary vs recomputed verdicts)",
           cross_layer,
           sum(1 for row in rows
               if row["verdict"] == "DENY" and not row["failed_layers"]))
    verify("figA binding vocabulary", sorted(binding["binding_result_counts"]),
           sorted(["UNDETERMINED", "EFFECT_MISMATCH", "RESOURCE_MISMATCH",
                   "TIME_MISMATCH", "PROFILE_MISMATCH", "PASS"]))
    verify("figA cross-layer denial ids length",
           len(binding["cross_layer_denial_ids"]), cross_layer)
    layers.append((
        "B — subject binding (join condition)",
        "Not a sixth artefact and not a sixth verifier: deterministic string "
        "agreement and interval containment over subject fields the five "
        "verifiers already read — required effect and required measurement "
        "profile (signed policy); effect, resource, issued_at (signed "
        "evidence); terminal narrowed grant and the intersection of the "
        "per-edge validity windows (delegation path); profile identifier "
        "(measurement fixture). Verifies no signature, takes no measurement, "
        "is not attestation of any runtime.",
    ))

    sizes = {
        "layer title": 8.4,
        "layer mechanism": 7.2,
        "layer count": 7.2,
        "conjunction": 9.0,
        "rule headline": 9.6,
        "rule detail": 7.2,
        "footnote": 7.0,
    }
    check_legibility(FIG_A, sizes)

    W = fig_width(FIG_A)
    margin = 0.05
    pad = 0.10
    box_x = margin
    box_w = W - 2 * margin
    title_h = sizes["layer title"] * LEAD / 72.0
    mech_h = sizes["layer mechanism"] * LEAD / 72.0
    detail_h = sizes["rule detail"] * LEAD / 72.0
    foot_line = sizes["footnote"] * LEAD / 72.0
    conj_h = sizes["conjunction"] * LEAD / 72.0

    # The failure count sits right-aligned on the title line, so a box is only
    # as tall as its own mechanism text: no uniform-height dead space.
    count_texts = [
        f"failure exercised in {occurrences[key]} of {total}" for key in keys
    ] + [f"decided the verdict in {cross_layer} of {total}"]
    title_w = max(
        text_width_in(W, t, sizes["layer title"], fontweight="bold")
        for t, _ in layers
    )
    count_w = max(
        text_width_in(W, c, sizes["layer count"], style="italic")
        for c in count_texts
    )
    mech_max = box_w - 2 * pad
    mech_lines = [
        wrap(W, mech, sizes["layer mechanism"], mech_max) for _, mech in layers
    ]
    assert title_w + count_w + 0.30 <= box_w - 2 * pad, "figA: title row too wide"
    box_heights = [
        0.09 + title_h + 0.02 + len(lines) * mech_h + 0.09 for lines in mech_lines
    ]
    gap = conj_h + 0.06  # room for the wedge between boxes
    arrow_h = 0.26

    rule_detail = wrap(
        W,
        "Non-compensable: any failed predicate denies and no predicate can "
        "compensate for another. A DENY carries first_rejecting_gate in the "
        "fixed evaluation order policy → evidence → state → authority → "
        "measurement → binding; B is consulted only when all five artefact "
        f"verifiers pass, so the {cross_layer} transactions it decided are "
        "denials with zero failing verifiers. Protocol validity is a separate "
        f"prior gate ({protocol['protocol_valid']}/{protocol['vectors']} "
        "vectors valid in the delegation laboratory).",
        sizes["rule detail"], box_w - 2 * pad,
    )
    headline = "ALLOW  iff  P ∧ E ∧ S ∧ A ∧ M ∧ B"
    sizes["rule headline"] = fit_fontsize(
        W, headline, sizes["rule headline"], box_w - 2 * pad, fontweight="bold")
    head_h = sizes["rule headline"] * LEAD / 72.0
    rule_h = 0.10 + head_h + 0.06 + len(rule_detail) * detail_h + 0.10

    foot = wrap(
        W,
        "Solid boxes are the five artefact verifiers; the dashed box is the "
        f"join condition over their subjects. Counts describe the designed "
        f"{total}-transaction corpus with author-written expected labels; "
        "they are not rates and do not estimate prevalence in any deployed "
        "system. State appraisal is structural, not cryptographic "
        "attestation; authority flags are corpus-supplied, not verified "
        "signatures; the binding stage compares corpus-supplied subject "
        "strings and is not attestation of any runtime.",
        sizes["footnote"], box_w,
    )
    foot_h = len(foot) * foot_line

    H = (0.08 + sum(box_heights) + (len(layers) - 1) * gap + arrow_h + rule_h
         + 0.16 + foot_h + 0.06)

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ax = inch_axes(fig, W, H)

    y_top = H - 0.08
    for i, ((title, _), lines) in enumerate(zip(layers, mech_lines)):
        bh = box_heights[i]
        y_bot = y_top - bh
        # The binding box is the last one and is drawn with a dashed edge, so
        # the figure distinguishes the join condition from the five artefact
        # verifiers by line style alone (house style: no colour, no fill).
        is_join = i == len(layers) - 1
        ax.add_patch(Rectangle((box_x, y_bot), box_w, bh, facecolor=WHITE,
                               edgecolor=BLACK, linewidth=1.1,
                               linestyle=((0, (4.5, 2.5)) if is_join else "-"),
                               joinstyle="miter"))
        ty = y_top - 0.09 - title_h / 2.0
        ax.text(box_x + pad, ty, title, ha="left", va="center",
                fontsize=sizes["layer title"], fontweight="bold")
        ax.text(box_x + box_w - pad, ty, count_texts[i], ha="right",
                va="center", fontsize=sizes["layer count"], style="italic")
        y = y_top - 0.09 - title_h - 0.02
        for line in lines:
            ax.text(box_x + pad, y - mech_h / 2.0, line, ha="left",
                    va="center", fontsize=sizes["layer mechanism"])
            y -= mech_h
        if i < len(layers) - 1:
            ax.text(W / 2.0, y_bot - gap / 2.0, "∧", ha="center", va="center",
                    fontsize=sizes["conjunction"], fontweight="bold")
            y_top = y_bot - gap
        else:
            y_top = y_bot

    ax.annotate("", xy=(W / 2.0, y_top - arrow_h), xytext=(W / 2.0, y_top),
                arrowprops={"arrowstyle": "-|>", "color": BLACK,
                            "linewidth": 1.2, "shrinkA": 0, "shrinkB": 0})
    rule_top = y_top - arrow_h
    rule_y = rule_top - rule_h
    ax.add_patch(Rectangle((box_x, rule_y), box_w, rule_h, facecolor=WHITE,
                           edgecolor=BLACK, linewidth=1.7, joinstyle="miter"))
    ax.text(W / 2.0, rule_top - 0.10 - head_h / 2.0, headline, ha="center",
            va="center", fontsize=sizes["rule headline"], fontweight="bold")
    y = rule_top - 0.10 - head_h - 0.06
    for line in rule_detail:
        ax.text(box_x + pad, y - detail_h / 2.0, line, ha="left", va="center",
                fontsize=sizes["rule detail"])
        y -= detail_h

    y = rule_y - 0.16
    for line in foot:
        ax.text(margin, y - foot_line / 2.0, line, ha="left", va="center",
                fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_A)


# ---------------------------------------------------------------------------
# figB -- policy-version x evidence-replay typed strict verdicts
# ---------------------------------------------------------------------------

FIG_B = "figB-policy-version-evidence-replay"


def fig_b() -> None:
    rows = load_jsonl(POLICY / "results" / "verdicts.jsonl")
    summary = load_json(POLICY / "results" / "summary.json")
    oracle = load_json(POLICY / "results-sql-oracle" / "summary.json")

    verify("figB vector count", len(rows), summary["vectors"])
    verify("figB strict expected matches",
           sum(1 for r in rows if r["expected_match"]),
           summary["strict_expected_matches"])
    verify("figB strict allows",
           sum(1 for r in rows if r["verdict"] == "ALLOW"),
           summary["strict_allows"])
    verify("figB strict denies",
           sum(1 for r in rows if r["verdict"] == "DENY"),
           summary["strict_denies"])
    verify("figB SQL re-composition agreement",
           oracle["implementation_matches"], summary["vectors"])
    gate_counts: dict[str, int] = {}
    for r in rows:
        gate_counts[r["first_rejecting_gate"]] = gate_counts.get(
            r["first_rejecting_gate"], 0) + 1
    verify("figB first-rejecting-gate histogram (verdicts vs SQL oracle)",
           gate_counts, dict(oracle["oracle_gate_counts"]))

    by_pair = {(r["declared_policy_state"], r["declared_evidence_state"]): r
               for r in rows}
    by_id = {r["id"]: r for r in rows}
    factorial_rows = ["correct", "missing", "stale", "substituted"]
    factorial_cols = ["good", "tampered", "replayed"]
    isolation_ids = summary["gate_isolation_ids"]
    verify("figB factorial cell count",
           len(factorial_rows) * len(factorial_cols),
           summary["families"]["factorial_4x3"])
    verify("figB gate-isolation row count", len(isolation_ids),
           summary["families"]["gate_isolation"])

    fa = {"presence_only": 0, "fail_open": 0}
    weak_allowed: set[str] = set()
    for r in rows:
        if r["verdict"] != "DENY":
            continue
        for profile in fa:
            if r["baselines"][profile] == "ALLOW":
                fa[profile] += 1
                weak_allowed.add(r["id"])
    verify("figB presence-only false allows", fa["presence_only"],
           summary["baseline_false_allows"]["presence_only"])
    verify("figB fail-open false allows", fa["fail_open"],
           summary["baseline_false_allows"]["fail_open"])

    sizes = {
        "column header": 8.2,
        "row label": 8.2,
        "cell verdict": 7.2,
        "corner label": 7.2,
        "section head": 7.8,
        "isolation row": 7.2,
        "footnote": 7.0,
    }
    check_legibility(FIG_B, sizes)

    W = fig_width(FIG_B)
    margin = 0.05
    label_w = max(
        text_width_in(W, r, sizes["row label"], fontweight="bold")
        for r in factorial_rows
    ) + 0.16
    grid_x = margin + label_w
    cell_w = (W - grid_x - margin) / len(factorial_cols)
    cell_line = sizes["cell verdict"] * LEAD / 72.0
    cell_h = 2 * cell_line + 0.26
    header_h = sizes["column header"] * LEAD / 72.0

    iso_line = sizes["isolation row"] * LEAD / 72.0 + 0.10
    head_line = sizes["section head"] * LEAD / 72.0
    foot_line = sizes["footnote"] * LEAD / 72.0
    foot = wrap(
        W,
        f"Strict typed verdicts. {summary['strict_expected_matches']}/"
        f"{summary['vectors']} agreement with author-written expected labels; "
        f"the relational re-composition agrees "
        f"{oracle['implementation_matches']}/{summary['vectors']} on verdict "
        "and rejecting gate, which is a second composition code path, not "
        "independent validation. This is reproduction of a frozen "
        "specification on designed vectors, not detection performance on any "
        "external workload.",
        sizes["footnote"], W - 2 * margin,
    ) + wrap(
        W,
        f"□  marks a strict deny that a weaker ablation profile falsely "
        f"allows: signed-policy presence {fa['presence_only']} of "
        f"{summary['strict_denies']} denies, missing-policy fail-open "
        f"{fa['fail_open']}. Ablations are author-defined experimental "
        "profiles, not named external products.",
        sizes["footnote"], W - 2 * margin,
    )

    H = (0.10 + header_h + len(factorial_rows) * cell_h + 0.30 + head_line
         + 0.06 + len(isolation_ids) * iso_line + 0.22 + len(foot) * foot_line
         + 0.06)

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ax = inch_axes(fig, W, H)

    grid_top = H - 0.10 - header_h
    for j, col in enumerate(factorial_cols):
        ax.text(grid_x + (j + 0.5) * cell_w, grid_top + header_h / 2.0, col,
                ha="center", va="center", fontsize=sizes["column header"],
                fontweight="bold")
    ax.text(margin, grid_top + header_h / 2.0, "policy \\ evidence", ha="left",
            va="center", fontsize=sizes["corner label"], style="italic")

    mark = 0.085
    for i, prow in enumerate(factorial_rows):
        y_bot = grid_top - (i + 1) * cell_h
        ax.text(grid_x - 0.10, y_bot + cell_h / 2.0, prow, ha="right",
                va="center", fontsize=sizes["row label"], fontweight="bold")
        for j, ecol in enumerate(factorial_cols):
            row = by_pair[(prow, ecol)]
            x = grid_x + j * cell_w
            ax.add_patch(Rectangle((x, y_bot), cell_w, cell_h, facecolor=WHITE,
                                   edgecolor=BLACK, linewidth=0.9,
                                   joinstyle="miter"))
            allow = row["verdict"] == "ALLOW"
            label = ("ALLOW\nverified" if allow
                     else f"DENY\n{row['first_rejecting_gate']}")
            ax.text(x + cell_w / 2.0, y_bot + cell_h / 2.0, label, ha="center",
                    va="center", fontsize=sizes["cell verdict"],
                    fontweight="bold" if allow else "normal",
                    linespacing=LEAD)
            if row["id"] in weak_allowed:
                ax.add_patch(Rectangle((x + 0.055, y_bot + cell_h - mark - 0.055),
                                       mark, mark, facecolor=WHITE,
                                       edgecolor=BLACK, linewidth=0.9,
                                       joinstyle="miter"))

    y = grid_top - len(factorial_rows) * cell_h - 0.30
    ax.text(margin, y - head_line / 2.0,
            "gate-isolation vectors (each fails exactly one strict policy gate):",
            ha="left", va="center", fontsize=sizes["section head"],
            fontweight="bold")
    y -= head_line + 0.06
    for vid in isolation_ids:
        row = by_id[vid]
        cy = y - iso_line / 2.0
        name = vid.replace("PSR_", "").replace("_good", "")
        ax.text(margin + 0.16, cy, f"{name} (good evidence)", ha="left",
                va="center", fontsize=sizes["isolation row"],
                family="DejaVu Sans Mono")
        ax.text(W - margin, cy, f"DENY  {row['first_rejecting_gate']}",
                ha="right", va="center", fontsize=sizes["isolation row"])
        if vid in weak_allowed:
            ax.add_patch(Rectangle((margin, cy - mark / 2.0), mark, mark,
                                   facecolor=WHITE, edgecolor=BLACK,
                                   linewidth=0.9, joinstyle="miter"))
        y -= iso_line

    y -= 0.22
    for line in foot:
        ax.text(margin, y - foot_line / 2.0, line, ha="left", va="center",
                fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_B)


# ---------------------------------------------------------------------------
# figC -- the four confidence-aware measurement fixtures
# ---------------------------------------------------------------------------

FIG_C = "figC-measurement-fixtures"


def fig_c() -> None:
    summary = load_json(COMPOSED / "results" / "summary.json")
    usage = summary["coverage"]["measurement_fixture_usage"]
    total = summary["transactions"]
    rows = load_jsonl(COMPOSED / "results" / "verdicts.jsonl")

    observed: dict[str, dict] = {}
    counted: dict[str, int] = {}
    source_of: dict[str, str] = {}
    for row in rows:
        m = row["measurement"]
        fid = m["fixture_id"]
        record = {
            "point": m["point_estimate"],
            "lcb": m["lcb"],
            "threshold": m["threshold"],
            "profile_digest": m["profile_digest"],
            "result": row["layer_results"]["measurement"],
        }
        if fid in observed:
            assert observed[fid] == record, f"figC: {fid} varies inside V4 verdicts"
        observed[fid] = record
        source_of[fid] = m["fixture_source"]
        counted[fid] = counted.get(fid, 0) + 1
    verify("figC fixture usage (verdicts vs summary coverage)",
           counted, dict(usage))

    # The corpus consumes two populations of measurement fixtures. figC plots
    # the four frozen SAFE fixtures; the cross-layer binding family adds two
    # laboratory-owned profile variants, which are asserted here to be exactly
    # the non-SAFE population and are NOT plotted as SAFE measurements.
    v3 = {f["id"]: f for f in load_json(
        SAFE_V3 / "results" / "measurement-fixtures.json")}
    safe_sourced = sorted(
        fid for fid, src in source_of.items() if src == "safe-v3-corpus")
    lab_owned = sorted(
        fid for fid, src in source_of.items() if src != "safe-v3-corpus")
    verify("figC SAFE-sourced fixture id set (V4 verdicts vs frozen v3 SAFE)",
           safe_sourced, sorted(v3))
    verify("figC laboratory-owned binding fixture id set",
           lab_owned,
           ["measurement_binding_alt_profile",
            "measurement_binding_main_profile"])
    verify("figC laboratory-owned binding fixture sources",
           sorted({source_of[fid] for fid in lab_owned}),
           ["composed-lab-binding-variant"])
    for fid in lab_owned:
        verify(f"figC {fid} typed result (unmodified SAFE evaluator passes it)",
               observed[fid]["result"], "PASS")
    for fid in safe_sourced:
        rec = observed[fid]
        verify(f"figC {fid} point estimate", rec["point"],
               v3[fid]["point_estimate"])
        verify(f"figC {fid} lower confidence bound", rec["lcb"], v3[fid]["lcb"])
        verify(f"figC {fid} threshold", rec["threshold"], v3[fid]["threshold"])
        verify(f"figC {fid} profile digest", rec["profile_digest"],
               v3[fid]["profile_digest"])
        verify(f"figC {fid} typed result", rec["result"], v3[fid]["result"])

    order = [
        ("measurement_supported", "supported"),
        ("measurement_point_only", "point-only\nboundary"),
        ("measurement_unsupported", "unsupported"),
        ("measurement_profile_mismatch", "altered\nprofile"),
    ]
    thresholds = {observed[fid]["threshold"] for fid, _ in order}
    assert len(thresholds) == 1, "figC: fixtures disagree on the threshold"
    threshold = thresholds.pop()
    verify("figC point-only-gate false allows (fixtures whose point clears "
           "the threshold but whose typed result is not PASS)",
           sum(1 for fid, _ in order
               if observed[fid]["point"] >= threshold
               and observed[fid]["result"] != "PASS"),
           2)

    sizes = {
        "tick label": 7.5,
        "axis label": 8.0,
        "value label": 7.1,
        "typed result": 7.5,
        "fixture n": 7.0,
        "threshold label": 7.1,
        "legend": 7.1,
        "footnote": 7.0,
    }
    check_legibility(FIG_C, sizes)

    # Coverage arithmetic stated on the face of the figure: the four plotted
    # fixtures do not account for the whole corpus, and the figure must not
    # let a reader infer that they do.
    plotted_usage = sum(usage[fid] for fid, _ in order)
    unplotted = total - plotted_usage
    verify("figC plotted-fixture usage plus laboratory-owned usage equals the "
           "transaction count",
           plotted_usage + sum(usage[fid] for fid in lab_owned), total)
    verify("figC unplotted transaction count",
           unplotted, sum(usage[fid] for fid in lab_owned))

    W = fig_width(FIG_C)
    margin = 0.05
    foot = wrap(
        W,
        "Designed boundary fixtures with author-chosen thresholds. The values "
        "are not measurements of any deployed model, and the n = 18 fixture "
        "sits where percentile-bootstrap bias is not negligible. The "
        "altered-profile fixture has scores identical to the supported "
        "fixture: its denial is driven by the profile digest alone. The four "
        f"plotted fixtures cover {plotted_usage} of the {total} transactions; "
        f"the remaining {unplotted} use two profile variants this laboratory "
        "owns in the same fixture schema, scored identically to the supported "
        "fixture and passed by the unmodified SAFE evaluator, which differ "
        "only in profile identity and are therefore not SAFE boundary cases.",
        sizes["footnote"], W - 2 * margin,
    )
    foot_line = sizes["footnote"] * LEAD / 72.0
    foot_h = len(foot) * foot_line

    plot_h = 2.34
    legend_h = 0.30
    tick_h = 2 * sizes["tick label"] * LEAD / 72.0 + 0.06
    H = 0.10 + plot_h + tick_h + legend_h + foot_h + 0.14

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ylabel_w = 0.60
    ax = fig.add_axes((
        ylabel_w / W,
        (foot_h + 0.14 + legend_h + tick_h) / H,
        1.0 - (ylabel_w + 0.10) / W,
        plot_h / H,
    ))

    for i, (fid, _) in enumerate(order):
        rec = observed[fid]
        ax.plot([i, i], [rec["lcb"], rec["point"]], color=BLACK, linewidth=1.2,
                solid_capstyle="butt")
        ax.plot([i], [rec["point"]], marker="o", markersize=6.2,
                markerfacecolor=BLACK, markeredgecolor=BLACK, linestyle="none")
        ax.plot([i], [rec["lcb"]], marker="s", markersize=6.2,
                markerfacecolor=WHITE, markeredgecolor=BLACK,
                markeredgewidth=1.2, linestyle="none")
        ax.annotate(f"{rec['point']:.6f}", (i, rec["point"]),
                    textcoords="offset points", xytext=(7, 1), ha="left",
                    va="center", fontsize=sizes["value label"])
        ax.annotate(f"{rec['lcb']:.6f}", (i, rec["lcb"]),
                    textcoords="offset points", xytext=(7, -1), ha="left",
                    va="center", fontsize=sizes["value label"])
        ax.text(i, 0.6335, rec["result"], ha="center", va="bottom",
                fontsize=sizes["typed result"], fontweight="bold")
        ax.text(i, 0.6185,
                f"n={v3[fid]['sample_count']}; used in {usage[fid]}/{total}",
                ha="center", va="bottom", fontsize=sizes["fixture n"])

    ax.axhline(threshold, color=BLACK, linestyle=(0, (5, 3)), linewidth=1.0)
    ax.text(3.56, threshold + 0.004, f"threshold {threshold:.2f}", ha="right",
            va="bottom", fontsize=sizes["threshold label"])

    ax.set_xticks(range(len(order)))
    ax.set_xticklabels([label for _, label in order],
                       fontsize=sizes["tick label"], linespacing=LEAD)
    ax.set_xlim(-0.52, 3.60)
    ax.set_ylim(0.610, 0.866)
    ax.set_yticks([0.65, 0.70, 0.75, 0.80, 0.85])
    ax.set_ylabel("integrated score", fontsize=sizes["axis label"])
    ax.tick_params(labelsize=sizes["tick label"], length=3)
    ax.spines[["top", "right"]].set_visible(False)

    ax.legend(
        handles=[
            Line2D([], [], marker="o", markersize=6.2, markerfacecolor=BLACK,
                   markeredgecolor=BLACK, linestyle="none",
                   label="point estimate (circle)"),
            Line2D([], [], marker="s", markersize=6.2, markerfacecolor=WHITE,
                   markeredgecolor=BLACK, markeredgewidth=1.2,
                   linestyle="none", label="5% bootstrap LCB (square)"),
            Line2D([], [], color=BLACK, linestyle=(0, (5, 3)), linewidth=1.0,
                   label=f"threshold {threshold:.2f} (dashed)"),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, -(tick_h + 0.04) / plot_h),
        ncol=3, frameon=False, fontsize=sizes["legend"], handlelength=1.9,
        columnspacing=0.9, handletextpad=0.4, borderpad=0.0,
    )

    y = foot_h + 0.06
    for line in foot:
        fig.text(margin / W, (y - foot_line / 2.0) / H, line, ha="left",
                 va="center", fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_C)


# ---------------------------------------------------------------------------
# figD -- TOPSIS closeness under two reference sets
# ---------------------------------------------------------------------------

FIG_D = "figD-topsis-reference-sets"


def fig_d() -> None:
    result = load_json(SAFE_V3 / "results" / "topsis-result.json")
    names = ["A", "B", "C"]

    dyn_base = result["dynamic_base_scores"]
    dyn_aug = result["dynamic_augmented_scores"]
    fix_base = result["fixed_base_scores"]
    fix_aug = result["fixed_augmented_scores"]
    verify("figD dynamic base score vector length", len(dyn_base), 3)
    verify("figD dynamic augmented score vector length", len(dyn_aug), 4)
    verify("figD fixed base score vector length", len(fix_base), 3)
    verify("figD fixed augmented score vector length", len(fix_aug), 4)

    def order_of(scores, k=3):
        return sorted(range(k), key=lambda i: -scores[i])

    verify("figD dynamic base order (recomputed from scores)",
           order_of(dyn_base), result["dynamic_base_order"])
    verify("figD dynamic augmented order of the original three",
           order_of(dyn_aug), result["dynamic_augmented_original_order"])
    verify("figD fixed base order (recomputed from scores)",
           order_of(fix_base), result["fixed_base_order"])
    verify("figD fixed augmented order of the original three",
           order_of(fix_aug), result["fixed_augmented_original_order"])
    verify("figD dynamic rank-reversal flag",
           result["dynamic_base_order"]
           != result["dynamic_augmented_original_order"],
           result["dynamic_rank_reversal"])
    verify("figD fixed rank-invariance flag",
           result["fixed_base_order"] == result["fixed_augmented_original_order"],
           result["fixed_rank_invariant"])
    verify("figD the two schemes disagree on the base ranking",
           result["dynamic_base_order"] != result["fixed_base_order"], True)

    sizes = {
        "panel title": 8.0,
        "tick label": 7.4,
        "axis label": 8.0,
        "series letter": 8.2,
        "value label": 7.0,
        "legend": 7.1,
        "footnote": 7.0,
    }
    check_legibility(FIG_D, sizes)

    markers = {"A": "o", "B": "s", "C": "^", "D": "D"}
    linestyles = {"A": "-", "B": (0, (5, 2)), "C": (0, (1.5, 1.5))}

    W = fig_width(FIG_D)
    margin = 0.05
    foot = wrap(
        W,
        "A constructed reproduction of a known reference-set sensitivity of "
        "TOPSIS. The two schemes disagree on the base ranking, so neither is "
        "a control for the other: the fixed scheme is a different ranking "
        "function that happens to be stable here, not a scheme that retained "
        "the dynamic scheme's original order. Frozen v3 SAFE fixture, "
        "consumed read-only.",
        sizes["footnote"], W - 2 * margin,
    )
    foot_line = sizes["footnote"] * LEAD / 72.0
    foot_h = len(foot) * foot_line

    plot_h = 2.10
    title_h = 2 * sizes["panel title"] * LEAD / 72.0 + 0.10
    tick_h = 2 * sizes["tick label"] * LEAD / 72.0 + 0.06
    legend_h = 0.26
    H = 0.08 + title_h + plot_h + tick_h + legend_h + foot_h + 0.14

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    left = 0.62 / W
    right = 1.0 - 0.06 / W
    gap = 0.60 / W
    panel_w = (right - left - gap) / 2.0
    bottom = (foot_h + 0.14 + legend_h + tick_h) / H

    lo = min(min(dyn_base), min(dyn_aug), min(fix_base), min(fix_aug))
    hi = max(max(dyn_base), max(dyn_aug), max(fix_base), max(fix_aug))
    pad = (hi - lo) * 0.10
    ylo, yhi = lo - pad, hi + pad
    min_gap = (yhi - ylo) * 0.058  # minimum label separation, data units

    def spread(values: list[float]) -> list[float]:
        """Deterministic label de-overlap: push near-equal labels apart."""
        idx = sorted(range(len(values)), key=lambda i: values[i])
        out = list(values)
        for k in range(1, len(idx)):
            prev, cur = idx[k - 1], idx[k]
            if out[cur] - out[prev] < min_gap:
                out[cur] = out[prev] + min_gap
        return out

    panels = [
        ("dynamic observed reference", dyn_base, dyn_aug),
        ("fixed 0–1 reference", fix_base, fix_aug),
    ]
    axes = []
    for p, (title, base, aug) in enumerate(panels):
        ax = fig.add_axes((left + p * (panel_w + gap), bottom, panel_w,
                           plot_h / H))
        axes.append(ax)
        base_labels = spread(list(base))
        aug_labels = spread(list(aug))
        for i, name in enumerate(names):
            ax.plot([0, 1], [base[i], aug[i]], color=BLACK,
                    linestyle=linestyles[name], linewidth=1.1,
                    marker=markers[name], markersize=5.4,
                    markerfacecolor=WHITE, markeredgecolor=BLACK,
                    markeredgewidth=1.0)
            ax.text(-0.86, base_labels[i], name, ha="left", va="center",
                    fontsize=sizes["series letter"], fontweight="bold")
            ax.text(-0.14, base_labels[i], f"{base[i]:.4f}", ha="right",
                    va="center", fontsize=sizes["value label"])
            ax.text(1.14, aug_labels[i], f"{aug[i]:.4f}", ha="left",
                    va="center", fontsize=sizes["value label"])
        ax.plot([1], [aug[3]], marker=markers["D"], markersize=5.4,
                markerfacecolor=BLACK, markeredgecolor=BLACK, linestyle="none")
        ax.text(1.14, aug_labels[3], f"{aug[3]:.4f}  D", ha="left",
                va="center", fontsize=sizes["value label"], fontweight="bold")
        ax.set_xlim(-0.90, 2.00)
        ax.set_ylim(ylo, yhi)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["base\n{A, B, C}", "augmented\n{A, B, C, D}"],
                           fontsize=sizes["tick label"], linespacing=LEAD)
        base_order = " > ".join(names[i] for i in order_of(base))
        aug_order = " > ".join(names[i] for i in order_of(aug))
        ax.set_title(f"{title}\n{base_order}  →  {aug_order}",
                     fontsize=sizes["panel title"], linespacing=LEAD)
        ax.tick_params(labelsize=sizes["tick label"], length=3)
        ax.spines[["top", "right"]].set_visible(False)
        if p == 1:
            ax.tick_params(labelleft=False)
    axes[0].set_ylabel("TOPSIS closeness", fontsize=sizes["axis label"])

    fig.legend(
        handles=[
            Line2D([], [], color=BLACK, linestyle=linestyles[n], linewidth=1.1,
                   marker=markers[n], markersize=5.4, markerfacecolor=WHITE,
                   markeredgecolor=BLACK, label=f"alternative {n}")
            for n in names
        ] + [
            Line2D([], [], color=BLACK, linestyle="none", marker=markers["D"],
                   markersize=5.4, markerfacecolor=BLACK,
                   markeredgecolor=BLACK, label="added alternative D"),
        ],
        loc="lower center",
        bbox_to_anchor=(0.5, (foot_h + 0.12) / H),
        ncol=4, frameon=False, fontsize=sizes["legend"], handlelength=2.1,
        columnspacing=0.9, handletextpad=0.4, borderpad=0.0,
    )

    y = foot_h + 0.06
    for line in foot:
        fig.text(margin / W, (y - foot_line / 2.0) / H, line, ha="left",
                 va="center", fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_D)


# ---------------------------------------------------------------------------
# figE -- pairwise co-failure matrix
# ---------------------------------------------------------------------------

FIG_E = "figE-cofailure-matrix"


def fig_e() -> None:
    summary = load_json(COMPOSED / "results" / "summary.json")
    matrix = summary["co_failure_matrix"]
    total = summary["transactions"]
    denies = summary["denies"]
    layers = ["policy", "evidence", "state", "authority", "measurement"]

    rows = load_jsonl(COMPOSED / "results" / "verdicts.jsonl")
    recomputed = {a: {b: 0 for b in layers} for a in layers}
    for row in rows:
        failed = set(row["failed_layers"])
        for a in failed:
            for b in failed:
                recomputed[a][b] += 1
    for a in layers:
        for b in layers:
            verify(f"figE cell [{a}][{b}]", recomputed[a][b], matrix[a][b])

    off_diagonal = [matrix[a][b] for a in layers for b in layers if a != b]
    assert len(off_diagonal) == 20, "figE: expected 20 off-diagonal cells"
    min_off = min(off_diagonal)
    verify("figE minimum off-diagonal cell", min_off,
           summary["co_failure_min_offdiagonal"])
    verify("figE no zero off-diagonal cell", min_off > 0,
           summary["co_failure_no_zero_offdiagonal"])
    for a in layers:
        verify(f"figE diagonal [{a}] equals failed_layer_occurrences",
               matrix[a][a], summary["failed_layer_occurrences"][a])
        for b in layers:
            verify(f"figE symmetry [{a}][{b}] == [{b}][{a}]",
                   matrix[a][b], matrix[b][a])

    # A denial with an empty failed-layer set contributes to no cell. The
    # matrix therefore does not cover the whole deny set, and says so.
    cross_layer = summary["binding_stage"]["cross_layer_denials"]
    verify("figE cross-layer denials absent from every cell",
           sum(1 for row in rows
               if row["verdict"] == "DENY" and not row["failed_layers"]),
           cross_layer)

    sizes = {
        "column header": 7.1,
        "row label": 7.1,
        "diagonal cell": 8.6,
        "off-diagonal cell": 8.0,
        "footnote": 7.0,
    }
    check_legibility(FIG_E, sizes)

    W = fig_width(FIG_E)
    margin = 0.05
    label_w = max(text_width_in(W, lab, sizes["row label"])
                  for lab in layers) + 0.12
    grid_x = margin + label_w
    cell = (W - grid_x - margin) / len(layers)
    header_h = sizes["column header"] * LEAD / 72.0

    foot = wrap(
        W,
        f"Diagonal (bold) = transactions in which the layer failed; "
        f"off-diagonal = transactions in which both layers failed, over "
        f"{total} transactions and {denies} denies. Every off-diagonal cell "
        f"is at least {min_off}: the corpus was engineered so that no cell is "
        "zero, so cell magnitudes reflect corpus construction, not failure "
        f"prevalence anywhere. The matrix ranges over the five artefact "
        f"verifiers only, so the {cross_layer} cross-layer denials — denials "
        "with an empty failed-layer set — appear in no cell of it. Counts on "
        "a designed corpus with author-written labels; they are not rates. "
        "State failures are structural-appraisal outcomes, not attestation "
        "verdicts of any runtime.",
        sizes["footnote"], W - 2 * margin,
    )
    foot_line = sizes["footnote"] * LEAD / 72.0
    H = (0.08 + header_h + len(layers) * cell + 0.20 + len(foot) * foot_line
         + 0.06)

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ax = inch_axes(fig, W, H)

    grid_top = H - 0.08 - header_h
    for j, lab in enumerate(layers):
        ax.text(grid_x + (j + 0.5) * cell, grid_top + header_h / 2.0, lab,
                ha="center", va="center", fontsize=sizes["column header"])
    for i, lab in enumerate(layers):
        y_bot = grid_top - (i + 1) * cell
        ax.text(grid_x - 0.06, y_bot + cell / 2.0, lab, ha="right",
                va="center", fontsize=sizes["row label"])
        for j, col in enumerate(layers):
            x = grid_x + j * cell
            ax.add_patch(Rectangle((x, y_bot), cell, cell, facecolor=WHITE,
                                   edgecolor=BLACK, linewidth=0.9,
                                   joinstyle="miter"))
            on_diagonal = i == j
            ax.text(x + cell / 2.0, y_bot + cell / 2.0, str(matrix[lab][col]),
                    ha="center", va="center",
                    fontsize=(sizes["diagonal cell"] if on_diagonal
                              else sizes["off-diagonal cell"]),
                    fontweight="bold" if on_diagonal else "normal")

    y = grid_top - len(layers) * cell - 0.20
    for line in foot:
        ax.text(margin, y - foot_line / 2.0, line, ha="left", va="center",
                fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_E)


# ---------------------------------------------------------------------------
# figF -- false allows by ablation, stratified by corpus family
# ---------------------------------------------------------------------------

FIG_F = "figF-stratified-false-allows"


def fig_f() -> None:
    summary = load_json(COMPOSED / "results" / "summary.json")
    by_family = summary["baseline_false_allows_by_family"]
    totals = summary["baseline_false_allows"]
    family_counts = summary["family_counts"]
    family_verdicts = summary["family_verdicts"]
    identity = summary["analytic_identities"][
        "four_of_five_equals_single_fault_denies"]
    refined = summary["analytic_identities"][
        "four_of_five_equals_single_fault_or_cross_layer"]

    rows = load_jsonl(COMPOSED / "results" / "verdicts.jsonl")
    recomputed: dict[str, dict[str, int]] = {}
    fam_n: dict[str, int] = {}
    fam_deny: dict[str, int] = {}
    for row in rows:
        fam = row["family"]
        fam_n[fam] = fam_n.get(fam, 0) + 1
        if row["verdict"] != "DENY":
            continue
        fam_deny[fam] = fam_deny.get(fam, 0) + 1
        bucket = recomputed.setdefault(fam, {})
        for ablation, verdict in row["baselines"].items():
            if verdict == "ALLOW":
                bucket[ablation] = bucket.get(ablation, 0) + 1
    verify("figF family sizes (verdicts vs summary)", fam_n, dict(family_counts))
    verify("figF family denies (verdicts vs summary)", fam_deny,
           {k: v["denies"] for k, v in family_verdicts.items()})
    verify("figF total denies", sum(fam_deny.values()), summary["denies"])

    families = [
        ("policy_evidence_measurement_factorial",
         "policy–evidence–\nmeasurement\nfactorial"),
        ("state_authority_measurement_cube",
         "state–authority–\nmeasurement\ncube"),
        ("authority_path_reuse", "authority\npath\nreuse"),
        ("cross_layer_joins", "cross-layer\njoins\n "),
        ("cross_layer_binding", "cross-layer\nbinding\n "),
    ]
    ablations = [
        ("point_only_measurement", "point-only measurement", ""),
        ("four_of_five_majority", "four-of-five majority", "///"),
        ("artifact_validity_only", "artifact validity / policy presence", "xxx"),
    ]
    assert len(families) == 5, "figF must be stratified by family, not aggregate"
    verify("figF family key set", sorted(k for k, _ in families),
           sorted(by_family))

    for fam_key, _ in families:
        for ab_key, _, _ in ablations:
            verify(f"figF bar [{fam_key}][{ab_key}]",
                   recomputed.get(fam_key, {}).get(ab_key, 0),
                   by_family[fam_key][ab_key])
    for ab_key, _, _ in ablations:
        verify(f"figF column total [{ab_key}]",
               sum(by_family[f][ab_key] for f, _ in families), totals[ab_key])
    # The v2 identity (four-of-five false allows == single-fault denies) is
    # broken by the existence of cross-layer denials and is asserted FALSE
    # here rather than deleted; the refined identity replaces it.
    verify("figF v2 four-of-five identity no longer holds",
           identity["holds"], False)
    verify("figF refined identity holds as set equality on identifiers",
           refined["holds"], True)
    verify("figF four-of-five total equals single-fault plus cross-layer",
           totals["four_of_five_majority"],
           refined["single_fault_deny_count"]
           + refined["cross_layer_denial_count"])
    verify("figF cross-layer denial count",
           refined["cross_layer_denial_count"],
           summary["binding_stage"]["cross_layer_denials"])

    sizes = {
        "tick label": 7.2,
        "axis label": 8.0,
        "bar label": 7.4,
        "legend": 7.3,
        "footnote": 7.0,
    }
    check_legibility(FIG_F, sizes)

    W = fig_width(FIG_F)
    margin = 0.05
    foot = wrap(
        W,
        f"Proof by construction plus corpus coverage on a designed "
        f"{summary['transactions']}-transaction corpus "
        f"({summary['denies']} strict denies). The four-of-five total "
        f"({totals['four_of_five_majority']}) is the "
        f"{refined['single_fault_deny_count']} single-fault denies plus the "
        f"{refined['cross_layer_denial_count']} cross-layer denials, verified "
        "as set equality on transaction identifiers, so it measures corpus "
        "composition and nothing else. A majority cannot represent a "
        "cross-layer denial at all: those transactions have zero failing "
        "verifiers. No bar is a rate or an estimate of behaviour in any "
        "deployed system. Ablations are author-defined experimental profiles, "
        "not representations of named external products.",
        sizes["footnote"], W - 2 * margin,
    )
    foot_line = sizes["footnote"] * LEAD / 72.0
    foot_h = len(foot) * foot_line

    plot_h = 2.22
    tick_h = 4 * sizes["tick label"] * LEAD / 72.0 + 0.08
    H = 0.10 + plot_h + tick_h + foot_h + 0.16

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ylabel_w = 0.58
    ax = fig.add_axes((
        ylabel_w / W,
        (foot_h + 0.16 + tick_h) / H,
        1.0 - (ylabel_w + 0.08) / W,
        plot_h / H,
    ))

    bar_w = 0.26
    for k, (ab_key, _, hatch) in enumerate(ablations):
        values = [by_family[fam_key][ab_key] for fam_key, _ in families]
        xs = [i + (k - 1) * bar_w for i in range(len(families))]
        ax.bar(xs, values, width=bar_w, facecolor=WHITE, edgecolor=BLACK,
               hatch=hatch, linewidth=1.0)
        for x, v in zip(xs, values):
            ax.annotate(str(v), (x, v), textcoords="offset points",
                        xytext=(0, 2.5), ha="center", va="bottom",
                        fontsize=sizes["bar label"])

    ax.set_xticks(range(len(families)))
    ax.set_xticklabels(
        [f"{label}\n(n={family_counts[key]}, "
         f"{family_verdicts[key]['denies']} denies)"
         for key, label in families],
        fontsize=sizes["tick label"], linespacing=LEAD,
    )
    ax.set_xlim(-0.55, len(families) - 0.45)
    ax.set_ylabel("false allows (count on this corpus)",
                  fontsize=sizes["axis label"])
    # Headroom is derived from the tallest bar, not hand-tuned, so the legend
    # block (three lines at the upper left) cannot collide with a bar top.
    tallest = max(by_family[f][a] for f, _ in families for a, _, _ in ablations)
    y_top = float(-(-int(tallest * 135) // 200) * 2)  # ceil(1.35*n/2)*2
    assert y_top >= tallest * 1.30, "figF: insufficient legend headroom"
    ax.set_ylim(0, y_top)
    ax.set_yticks([t for t in range(0, int(y_top), 2)])
    ax.tick_params(labelsize=sizes["tick label"], length=3)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(
        handles=[
            Patch(facecolor=WHITE, edgecolor=BLACK, hatch=hatch,
                  label=f"{label} (total {totals[key]})")
            for key, label, hatch in ablations
        ],
        loc="upper left", frameon=False, fontsize=sizes["legend"],
        handlelength=1.8, handletextpad=0.5, labelspacing=0.3, borderpad=0.2,
    )

    y = foot_h + 0.06
    for line in foot:
        fig.text(margin / W, (y - foot_line / 2.0) / H, line, ha="left",
                 va="center", fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_F)


# ---------------------------------------------------------------------------
# figG -- the cross-layer denial class: every artefact verifier passes and the
# composition still refuses. This is the transaction class that could not be
# represented before the binding stage existed, so it needs its own figure.
# ---------------------------------------------------------------------------

FIG_G = "figG-cross-layer-denials"

# Which pair of subject fields each typed binding result is decided by. Only
# selects the sentence shape; every value printed is read from the
# transaction's own binding record.
BINDING_SUBJECT = {
    "EFFECT_MISMATCH": ("effect", "effect_matches_policy"),
    "RESOURCE_MISMATCH": ("resource", "resource_matches_canonical"),
    "TIME_MISMATCH": ("issued_at", "issued_at_within_authorised_window"),
    "PROFILE_MISMATCH": ("measurement_profile",
                         "measurement_profile_matches_policy"),
}

FAMILY_G = "cross_layer_binding"


def _fmt_list(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


def _subject_line(row: dict) -> str:
    """One sentence naming the disagreeing reported fields."""
    details = row["binding"]["details"]
    observed = details["observed_effect"]
    canonical = details["canonical_action"]
    result = row["binding"]["result"]
    if result == "EFFECT_MISMATCH":
        return (f"reported {observed['effect']} on {observed['resource']}"
                f"  ·  policy requires {canonical['effect']}  ·  terminal "
                f"grant {_fmt_list(canonical['granted_tools'])} on "
                f"{_fmt_list(canonical['granted_resources'])}")
    if result == "RESOURCE_MISMATCH":
        return (f"reported resource {observed['resource']}  ·  authorised "
                f"resource {canonical['resource']}  ·  terminal grant "
                f"{_fmt_list(canonical['granted_resources'])}")
    if result == "TIME_MISMATCH":
        return (f"reported issued_at {observed['issued_at']}  ·  path valid "
                f"[{canonical['authorised_from']}, "
                f"{canonical['authorised_until']}]")
    if result == "PROFILE_MISMATCH":
        return (f"appraised under {observed['measurement_profile']}  ·  "
                f"policy requires {canonical['measurement_profile']}")
    raise AssertionError(f"figG: unhandled binding result {result!r}")


def fig_g() -> None:
    summary = load_json(COMPOSED / "results" / "summary.json")
    total = summary["transactions"]
    binding = summary["binding_stage"]
    rows = load_jsonl(COMPOSED / "results" / "verdicts.jsonl")

    family = [row for row in rows if row["family"] == FAMILY_G]
    verify("figG family size (verdicts vs summary family_counts)",
           len(family), summary["family_counts"][FAMILY_G])

    # Every row of this family, denials and controls alike, is constructed so
    # that all five artefact verifiers pass. Asserted per row rather than
    # asserted once in prose.
    passing = {"policy": "PASS", "evidence": "PASS", "state": "PASS",
               "authority": "ALLOW", "measurement": "PASS"}
    for row in family:
        rid = row["id"]
        verify(f"figG {rid} all five artefact verifiers pass",
               row["layer_results"], passing)
        verify(f"figG {rid} failed-layer set is empty", row["failed_layers"], [])
        verify(f"figG {rid} binding result (verdict stream vs expected label)",
               row["binding"]["result"], row["expected"]["binding_result"])
        verify(f"figG {rid} verdict (verdict stream vs expected label)",
               row["verdict"], row["expected"]["verdict"])
        verify(f"figG {rid} subject record re-derived by the verifier",
               row["binding"]["subject_match"], True)

    denials = [row for row in family if row["binding"]["result"] != "PASS"]
    controls = [row for row in family if row["binding"]["result"] == "PASS"]
    verify("figG cross-layer denial identifiers (recomputed vs summary)",
           sorted(row["id"] for row in denials),
           sorted(binding["cross_layer_denial_ids"]))
    verify("figG cross-layer denial count (recomputed vs summary)",
           len(denials), binding["cross_layer_denials"])
    verify("figG cross-layer denials all live in this family",
           binding["cross_layer_denials_by_family"][FAMILY_G],
           binding["cross_layer_denials"])
    recomputed_results: dict[str, int] = {}
    for row in family:
        key = row["binding"]["result"]
        recomputed_results[key] = recomputed_results.get(key, 0) + 1
    verify("figG binding-result histogram for this family "
           "(verdicts vs summary)",
           recomputed_results,
           {k: v for k, v in
            binding["binding_result_counts_by_family"][FAMILY_G].items()
            if v},
           )
    for row in denials:
        rid = row["id"]
        verify(f"figG {rid} verdict is DENY", row["verdict"], "DENY")
        verify(f"figG {rid} first rejecting gate is the binding gate",
               row["first_rejecting_gate"], row["binding"]["gate"])
        field, flag = BINDING_SUBJECT[row["binding"]["result"]]
        verify(f"figG {rid} deciding subject predicate {flag} is false",
               row["binding"]["details"][flag], False)
        verify(f"figG {rid} printed reported {field} equals the record",
               _subject_line(row).count(
                   str(row["binding"]["details"]["observed_effect"][field])),
               1)
    for row in controls:
        rid = row["id"]
        verify(f"figG {rid} verdict is ALLOW", row["verdict"], "ALLOW")
        verify(f"figG {rid} first rejecting gate is 'verified'",
               row["first_rejecting_gate"], "verified")
        verify(f"figG {rid} has no missing subject field",
               row["binding"]["details"]["missing_subject_fields"], [])

    # Order: denials grouped by the rule that fired, in the rule's own order;
    # controls in corpus order. Deterministic, no sorting by value.
    rule_order = ["EFFECT_MISMATCH", "RESOURCE_MISMATCH", "TIME_MISMATCH",
                  "PROFILE_MISMATCH"]
    denials = sorted(
        denials,
        key=lambda r: (rule_order.index(r["binding"]["result"]),
                       [x["id"] for x in family].index(r["id"])),
    )

    sizes = {
        "lead": 8.4,
        "preamble": 7.2,
        "section head": 7.8,
        "row id": 7.0,
        "row result": 7.2,
        "row verdict": 7.2,
        "subject line": 7.0,
        "control id": 7.0,
        "footnote": 7.0,
    }
    check_legibility(FIG_G, sizes)

    W = fig_width(FIG_G)
    margin = 0.05
    indent = 0.12
    mono = {"family": "DejaVu Sans Mono"}

    short_ids = {row["id"]: row["id"].replace("XLB_", "") for row in family}
    id_w = max(text_width_in(W, short_ids[r["id"]], sizes["row id"], **mono)
               for r in denials)
    result_w = max(
        text_width_in(W, r["binding"]["result"], sizes["row result"],
                      fontweight="bold")
        for r in denials
    )
    verdict_w = max(
        text_width_in(W, v, sizes["row verdict"], fontweight="bold")
        for v in ("DENY", "ALLOW")
    )
    verdict_x = W - margin
    result_x = verdict_x - verdict_w - 0.16
    assert margin + indent + id_w + 0.20 <= result_x - result_w, (
        "figG: identifier column collides with the result column"
    )

    lead_h = sizes["lead"] * LEAD / 72.0
    pre_h = sizes["preamble"] * LEAD / 72.0
    head_h = sizes["section head"] * LEAD / 72.0
    row_a_h = sizes["row result"] * LEAD / 72.0
    subj_h = sizes["subject line"] * LEAD / 72.0
    ctl_h = sizes["control id"] * LEAD / 72.0
    foot_line = sizes["footnote"] * LEAD / 72.0

    lead = wrap(
        W,
        f"{len(denials)} of {total} transactions: every artefact verifier "
        "passes and the composition denies.",
        sizes["lead"], W - 2 * margin, fontweight="bold",
    )
    preamble = wrap(
        W,
        f"All {len(family)} transactions of the {FAMILY_G} family. In every "
        "row below the five artefact verifiers return policy PASS, evidence "
        "PASS, state PASS, authority ALLOW and measurement PASS, and the "
        "failed-layer set is empty; only agreement over the implemented "
        "effect/resource/report-time/profile coordinates varies. The "
        "binding stage is the join condition of the composition rule, not a "
        "sixth artefact verifier.",
        sizes["preamble"], W - 2 * margin,
    )
    subject_lines = [
        wrap(W, _subject_line(row), sizes["subject line"],
             W - margin - indent - 0.30 - margin)
        for row in denials
    ]
    control_text = "  ·  ".join(short_ids[row["id"]] for row in controls)
    control_lines = wrap(W, control_text, sizes["control id"],
                         W - margin - indent - margin, **mono)
    foot = wrap(
        W,
        "The binding stage is deterministic string agreement and interval "
        "containment over subject fields read out of corpus-supplied "
        "artefacts: it verifies no signature, takes no measurement, contacts "
        "no attestation service and is not attestation of any runtime. Its "
        "denials are denials on a designed corpus with author-written "
        "expected labels — coverage, not a rate, and not an estimate of how "
        "often such disagreement arises in any deployed system. Both window "
        "boundaries are inclusive, which is what the two boundary controls "
        "exercise. The controls are matched by construction and differ from "
        "the denials only in the reported subject fields, so a verifier that refused "
        "everything would fail them.",
        sizes["footnote"], W - 2 * margin,
    )

    rows_h = sum(row_a_h + 0.02 + len(lines) * subj_h + 0.07
                 for lines in subject_lines)
    H = (0.08 + len(lead) * lead_h + 0.06 + len(preamble) * pre_h + 0.16
         + head_h + 0.06 + rows_h + 0.10 + head_h + 0.05
         + len(control_lines) * ctl_h + 0.18 + len(foot) * foot_line + 0.06)

    fig = plt.figure(figsize=(W, H), dpi=DPI)
    ax = inch_axes(fig, W, H)

    y = H - 0.08
    for line in lead:
        ax.text(margin, y - lead_h / 2.0, line, ha="left", va="center",
                fontsize=sizes["lead"], fontweight="bold")
        y -= lead_h
    y -= 0.06
    for line in preamble:
        ax.text(margin, y - pre_h / 2.0, line, ha="left", va="center",
                fontsize=sizes["preamble"])
        y -= pre_h

    y -= 0.16
    ax.plot([margin, W - margin], [y, y], color=BLACK, linewidth=1.0,
            solid_capstyle="butt")
    y -= head_h
    ax.text(margin, y + head_h / 2.0,
            f"denied at the binding gate — {len(denials)} of {len(family)}",
            ha="left", va="center", fontsize=sizes["section head"],
            fontweight="bold")
    ax.text(verdict_x, y + head_h / 2.0, "verdict", ha="right", va="center",
            fontsize=sizes["section head"], style="italic")
    ax.text(result_x, y + head_h / 2.0, "binding result", ha="right",
            va="center", fontsize=sizes["section head"], style="italic")
    y -= 0.06

    for row, lines in zip(denials, subject_lines):
        ax.text(margin + indent, y - row_a_h / 2.0, short_ids[row["id"]],
                ha="left", va="center", fontsize=sizes["row id"], **mono)
        ax.text(result_x, y - row_a_h / 2.0, row["binding"]["result"],
                ha="right", va="center", fontsize=sizes["row result"],
                fontweight="bold")
        ax.text(verdict_x, y - row_a_h / 2.0, row["verdict"], ha="right",
                va="center", fontsize=sizes["row verdict"], fontweight="bold")
        y -= row_a_h + 0.02
        for line in lines:
            ax.text(margin + indent + 0.18, y - subj_h / 2.0, line, ha="left",
                    va="center", fontsize=sizes["subject line"])
            y -= subj_h
        y -= 0.07

    y -= 0.10
    ax.plot([margin, W - margin], [y, y], color=BLACK, linewidth=1.0,
            solid_capstyle="butt")
    y -= head_h
    ax.text(margin, y + head_h / 2.0,
            "matched controls — same construction, agreeing implemented coordinates",
            ha="left", va="center", fontsize=sizes["section head"],
            fontweight="bold")
    ax.text(verdict_x, y + head_h / 2.0,
            f"{len(controls)} of {len(controls)} ALLOW", ha="right",
            va="center", fontsize=sizes["section head"], fontweight="bold")
    y -= 0.05
    for line in control_lines:
        ax.text(margin + indent, y - ctl_h / 2.0, line, ha="left", va="center",
                fontsize=sizes["control id"], **mono)
        y -= ctl_h

    y -= 0.18
    for line in foot:
        ax.text(margin, y - foot_line / 2.0, line, ha="left", va="center",
                fontsize=sizes["footnote"])
        y -= foot_line

    save(fig, FIG_G)


# ---------------------------------------------------------------------------

BUILDERS = [
    (FIG_A, fig_a),
    (FIG_B, fig_b),
    (FIG_C, fig_c),
    (FIG_D, fig_d),
    (FIG_E, fig_e),
    (FIG_F, fig_f),
    (FIG_G, fig_g),
]


def main() -> int:
    assert sorted(EMBED_FRACTION) == sorted(stem for stem, _ in BUILDERS)
    print(f"building the {len(BUILDERS)} canonical figures")
    for _, builder in BUILDERS:
        builder()
    for fig in _RULER.values():
        plt.close(fig)

    print("\nlegibility contract "
          "(effective_pt = font_pt * (6.1in * embed_fraction / figwidth_in)):")
    print(f"{'figure':<36} {'width_in':>8} {'embed_in':>8} {'scale':>6}  "
          f"{'smallest element':<20} {'pt':>5} {'eff_pt':>7}")
    for stem, width_in, embed_in, scale, name, pt, eff in LEGIBILITY_REPORT:
        print(f"{stem:<36} {width_in:>8.3f} {embed_in:>8.3f} {scale:>6.3f}  "
              f"{name:<20} {pt:>5.1f} {eff:>7.2f}")

    print(f"\n{len(VERIFICATION)} plotted values verified against source JSON")
    return 0


if __name__ == "__main__":
    sys.exit(main())
