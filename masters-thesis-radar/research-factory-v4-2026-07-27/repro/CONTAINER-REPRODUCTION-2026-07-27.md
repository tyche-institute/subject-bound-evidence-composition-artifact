# Isolated-container reproduction of the V4 laboratory entry points

Review experiment **E4 (cross-host closure)**, executed 2026-07-27.
Closes review finding **C-25**: every `run-metadata.json` in this packet
carries `"network_used": false`, which is an assertion an entry point makes
about itself, not a measurement. This run replaces the assertion with an
enforced property.

Scope note, stated once and meant literally: this is **one container, on the
same kernel, on the same x86-64 host**. It closes cross-*environment*
reproduction. It does not close cross-*host*, cross-*architecture* or
cross-*CPU-dispatch* reproduction, and nothing below should be read as
evidence for those.

---

## 1. What was executed

| # | Entry point | Commands |
| --- | --- | --- |
| 1 | `labs/protocol-valid-unauthorized` | `verify_corpus.py`, `adapters/boundary_seal_adapter.py`, `verify_delegation_paths.py`, `run_sql_oracle.py` (the sequence documented in that laboratory's `README.md`; it has no `run.sh`) |
| 2 | `labs/policy-version-evidence-replay/run.sh` | `build_corpus.py`, `run.py`, `run_sql_oracle.py`, self-check |
| 3 | `labs/composed-transaction-corpus/run.sh` | `test_state_adapter.py`, `build_corpus.py`, `verify_transactions.py`, `run_sql_oracle.py`, self-check |

The `sha256sum -c SHA256SUMS` step inside both `run.sh` files is
self-referential — the runner writes `SHA256SUMS` in the same invocation, so
it verifies the run against itself and is **not** the comparison reported
here. The comparison in §5 is against the host-resident result files,
captured before the container was started and re-captured after it exited.

### Inputs mounted read-only

The packet's own entry points reach outside the packet directory. Both
external trees are mounted read-only at the exact relative positions the code
resolves:

| Host path | Container path | Why |
| --- | --- | --- |
| `.../research-factory-v4-2026-07-27` | `/work/masters-thesis-radar/research-factory-v4-2026-07-27` | the packet |
| `.../research-factory-v3-2026-07-25` | `/work/masters-thesis-radar/research-factory-v3-2026-07-25` | `verify_transactions.py` loads the SAFE measurement module and corpus from `V3_FACTORY/labs/safe-metric-metamorphics` |
| `<vault>/a2a-boundary-seal/results/extension-enabled` | `/work/a2a-boundary-seal/results/extension-enabled` | `boundary_seal_adapter.py` reads `send-message.json` and `agent-card.json` from `ADAPTER_DIR.parents[4]/a2a-boundary-seal` |

`/work` is read-only throughout. The container copies `/work` to `/scratch`,
a tmpfs, and runs everything there, so the host packet cannot be written even
by accident. The container additionally runs with `--read-only`, so the only
writable paths in the whole filesystem are the two tmpfs mounts.

**Verified after the run:** all 27 host result files plus the 4 host corpus
artefacts hash identically to their pre-run values — the host packet was not
touched.

---

## 2. Image identity

| Item | Value |
| --- | --- |
| Base image | `python:3.12-slim`, pinned **by digest** in the `FROM` line |
| Base repo digest | `sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de` |
| Base image created | 2026-07-14T02:11:29Z, `linux/amd64` |
| Built image | `tyche-v4-repro:2026-07-27` |
| Built image id | `sha256:e9d09e11129b6b53734d780c21fa90d1d92cf7e5f508357704c5fd34e319a173` |
| Build command | `docker build --network=none --pull=false -f repro/Dockerfile -t tyche-v4-repro:2026-07-27 <ctx>` |
| Run command | `docker run --rm --network=none --read-only --tmpfs /scratch --tmpfs /tmp -v ...:ro tyche-v4-repro:2026-07-27` |

The tag is not trusted: `FROM python:3.12-slim@sha256:57cd7c3a…` means the
tag cannot drift under this experiment.

## 3. Pinned versions

`repro/requirements.txt` pins with `==`:

```
numpy==2.5.0
cryptography==49.0.0
cffi==2.0.0
pycparser==3.0
```

`numpy` and `cryptography` are the two versions the laboratories themselves
record in `results/run-metadata.json`. `cffi` and `pycparser` are not
recorded anywhere in the packet; they are the runtime dependency closure of
`cryptography 49.0.0` (`Requires-Dist: cffi>=2.0.0`) and are pinned to the
host's installed versions so the closure is fixed rather than floating.

Installed with `pip install --no-index --find-links=<wheelhouse>`, so a
missing wheel is a hard build failure rather than a silent reach for an
index.

### Wheelhouse provenance — read this before trusting §7

This run had no network. The wheels were therefore **not downloaded**; they
were extracted from the host's local pip HTTP cache by
`repro/collect-wheels.py`, which accepts a cached body only when the zip's
`<name>-<version>.dist-info` matches a pin, and reconstructs the wheel
filename from the wheel's own `Tag:` lines.

| Wheel | SHA-256 |
| --- | --- |
| `numpy-2.5.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `aaa760137137e8d3c920d27927748215b56014f92667dc9b6c27dfc61249255a` |
| `cryptography-49.0.0-cp311-abi3-manylinux_2_34_x86_64.whl` | `cbc77da8c523d5abd028635ba850a6966fcee2c82e2bf65a41d1d8afe0f98be9` |
| `cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba` |
| `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` |

**Consequence that must not be glossed over.** These are the same manylinux
wheels the host has installed (same version, same compressed tag set). The
container's NumPy is therefore the *same compiled binary* as the host's. This
reproduction consequently says **nothing** about whether the bootstrap lower
bound moves across NumPy *builds* — the exact question the review raised. That
question is answered separately, and by a different measurement, in §7.

## 4. The enforced no-network property (C-25)

`--network=none` was passed to **both** `docker build` and `docker run`. The
build succeeded with no network namespace because the base image was already
in the local daemon store and the wheels came from the build context.

Measured inside the running container, before any laboratory executed:

```
interfaces in this network namespace:
lo
routes:
Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
        (no route entries)
outbound TCP connect: FAILED errno=101 (ENETUNREACH) Network is unreachable
```

The connect target was a literal IPv4 address with no DNS lookup; with no
non-loopback interface and no route, the kernel fails the call locally and no
packet can leave the machine.

What this does and does not establish, precisely:

- **Established:** during this run the entry points *could not* have used the
  network, because no usable network namespace existed. The
  `"network_used": false` claim is, for this execution, a measured property
  of the sandbox rather than a self-report.
- **Not established:** that the entry points contain no network code. A
  static claim about the code is not what was measured. The
  `network_used_note` string inside the two `run-metadata.json` files —
  "declared property of the entry points, not an enforced sandbox
  measurement" — remains literally true of those files, because the runners
  still write the key unconditionally without checking anything. This report,
  not the metadata key, is the evidence.

## 5. Per-file comparison

Host baseline captured from the packet immediately before the run. (There is
no git repository at the vault root, so "host" here means the result files
resident in the packet tree at 2026-07-27; it does not mean a git commit.)

27 result files under `labs/*/results*/`, plus the 4 input artefacts that the
entry points regenerate.

| # | File (relative to `labs/`) | Host SHA-256 | Container SHA-256 | Match |
| ---: | --- | --- | --- | :--: |
| 1 | `composed-transaction-corpus/results/verdicts.jsonl` | `a942d653…cb0d1378` | `a942d653…cb0d1378` | ✔ |
| 2 | `composed-transaction-corpus/results/summary.json` | `ff0ef1d9…3265157f` | `ff0ef1d9…3265157f` | ✔ |
| 3 | `composed-transaction-corpus/results/run-metadata.json` | `bc8f25ff…996b71be` | `aa5cda08…705a9dde` | ✘ |
| 4 | `composed-transaction-corpus/results/SHA256SUMS` | `21e926a2…f49d0c76` | `0e36a0a3…93de20a9` | ✘ |
| 5 | `composed-transaction-corpus/results-sql-oracle/verdicts.jsonl` | `36b53707…5496cc85` | `36b53707…5496cc85` | ✔ |
| 6 | `composed-transaction-corpus/results-sql-oracle/summary.json` | `9af45780…e911fbf8` | `9af45780…e911fbf8` | ✔ |
| 7 | `composed-transaction-corpus/results-sql-oracle/SHA256SUMS` | `ce7d2ff7…f591c0ef` | `ce7d2ff7…f591c0ef` | ✔ |
| 8 | `policy-version-evidence-replay/results/verdicts.jsonl` | `cfc8bcdf…be22210b` | `cfc8bcdf…be22210b` | ✔ |
| 9 | `policy-version-evidence-replay/results/summary.json` | `e8abc711…daf011f7` | `e8abc711…daf011f7` | ✔ |
| 10 | `policy-version-evidence-replay/results/run-metadata.json` | `f808c9d4…cc6daaa9` | `740f713c…ad14241e` | ✘ |
| 11 | `policy-version-evidence-replay/results/SHA256SUMS` | `30cad467…b2d34cf7` | `46125149…3e9118db` | ✘ |
| 12 | `policy-version-evidence-replay/results-sql-oracle/verdicts.jsonl` | `fef5ce75…bea776b3` | `fef5ce75…bea776b3` | ✔ |
| 13 | `policy-version-evidence-replay/results-sql-oracle/summary.json` | `3ae9fb6b…45298777` | `3ae9fb6b…45298777` | ✔ |
| 14 | `policy-version-evidence-replay/results-sql-oracle/SHA256SUMS` | `939bd87c…c5f4346c` | `939bd87c…c5f4346c` | ✔ |
| 15 | `protocol-valid-unauthorized/results/verdicts.jsonl` | `a4cccd2a…d01f00ab` | `a4cccd2a…d01f00ab` | ✔ |
| 16 | `protocol-valid-unauthorized/results/summary.json` | `d275c7d9…20efc247` | `d275c7d9…20efc247` | ✔ |
| 17 | `protocol-valid-unauthorized/results/SHA256SUMS` | `965c656e…cb9904d8` | `965c656e…cb9904d8` | ✔ |
| 18 | `protocol-valid-unauthorized/results-boundary-adapter/verdicts.jsonl` | `3c75e42e…e6d3dc7b` | `3c75e42e…e6d3dc7b` | ✔ |
| 19 | `protocol-valid-unauthorized/results-boundary-adapter/summary.json` | `46f54edc…0f062990` | `46f54edc…0f062990` | ✔ |
| 20 | `protocol-valid-unauthorized/results-boundary-adapter/SHA256SUMS` | `51ab2316…c27037b4` | `51ab2316…c27037b4` | ✔ |
| 21 | `protocol-valid-unauthorized/results-delegation-paths/verdicts.jsonl` | `ba1554b3…c0832d18` | `ba1554b3…c0832d18` | ✔ |
| 22 | `protocol-valid-unauthorized/results-delegation-paths/summary.json` | `927ad31e…083c85b4` | `927ad31e…083c85b4` | ✔ |
| 23 | `protocol-valid-unauthorized/results-delegation-paths/expanded-cases.json` | `b6a47b40…1427fa73` | `b6a47b40…1427fa73` | ✔ |
| 24 | `protocol-valid-unauthorized/results-delegation-paths/SHA256SUMS` | `7b83e7c6…c5646c4f` | `7b83e7c6…c5646c4f` | ✔ |
| 25 | `protocol-valid-unauthorized/results-sql-oracle/verdicts.jsonl` | `8d846c5a…ae2f7735` | `8d846c5a…ae2f7735` | ✔ |
| 26 | `protocol-valid-unauthorized/results-sql-oracle/summary.json` | `e8a06d8c…a128973a` | `e8a06d8c…a128973a` | ✔ |
| 27 | `protocol-valid-unauthorized/results-sql-oracle/SHA256SUMS` | `ea14daa6…3bd2d919` | `ea14daa6…3bd2d919` | ✔ |
| A | `composed-transaction-corpus/corpus.json` (regenerated by entry point 3) | `300fcf3e…1d9f0e7c` | `300fcf3e…1d9f0e7c` | ✔ |
| B | `policy-version-evidence-replay/corpus.json` (regenerated by entry point 2) | `8d1925bf…d9dd45da` | `8d1925bf…d9dd45da` | ✔ |
| C | `protocol-valid-unauthorized/corpus.json` (read-only input) | `f3548df9…47e2f16e` | `f3548df9…47e2f16e` | ✔ |
| D | `protocol-valid-unauthorized/delegation-paths.json` (read-only input) | `2b93fe67…5baab45e` | `2b93fe67…5baab45e` | ✔ |

Digests are abbreviated as first-8…last-8; the full 64-hex values were
compared, not the abbreviations.

**Result: 23 of 27 result files byte-identical; 4 differ. All 4 regenerated /
input corpus artefacts byte-identical.**

### The 4 divergences, exactly

Two of them are the `run-metadata.json` files. Their full contents were dumped
from the container and diffed against the host copies. Every key is identical
except `python` and `platform`:

| Key | Host | Container |
| --- | --- | --- |
| `python` | `3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]` | `3.12.13 (main, Jul 14 2026, 02:09:00) [GCC 14.2.0]` |
| `platform` | `Linux-6.8.0-136-generic-x86_64-with-glibc2.39` | `Linux-6.8.0-136-generic-x86_64-with-glibc2.41` |

Everything else in both files — `numpy: 2.5.0`, `cryptography: 49.0.0`,
`network_used: false`, `network_used_note`, `evaluation_order`,
`state_decision_time`, `argv` — is unchanged. These two files exist to record
the environment; a byte-identical `run-metadata.json` across two different
environments would mean the file was not doing its job.

Note that the kernel string is identical on both sides (`6.8.0-136-generic`).
That is the container sharing the host kernel, and it is precisely why this
run is not a cross-host result.

The other two divergences are the two `results/SHA256SUMS` files. Both were
dumped in full. Each differs from its host counterpart in **exactly one
line** — the line hashing `run-metadata.json`:

```
composed-transaction-corpus/results/SHA256SUMS
- bc8f25ff9b4b4fdd1eab696f6c752568caccea4c4c7eefff3b4f7c69996b71be  run-metadata.json
+ aa5cda085802c05e7edb268024fd0b2dc76beb23e70df26fb76a677a705a9dde  run-metadata.json

policy-version-evidence-replay/results/SHA256SUMS
- f808c9d438e6d3507ccd91af9714744969053720225f3c836b9458d2cc6daaa9  run-metadata.json
+ 740f713cd05b3bf682f76cc89412acebce94b6bea7e49c3bf9b42de3ad14241e  run-metadata.json
```

Line counts are equal on both sides (12 and 6), and a positional line-by-line
comparison reports exactly one differing line in each file — line 3, shown
above. All other lines are identical, including the hashes of
`verdicts.jsonl`, `summary.json`, `corpus.json`, the runners,
`composition_rule.py`, `state_adapter.py`, `state-fixtures.json`, and the
cross-tree reference to the v3 SAFE `run.py`
(`49df03d61b9ba2b6ea2dd8b9db84977de9fc6643f243b0db10884d424a20e277`). Both
`SHA256SUMS` files use relative paths on both sides.

No experimental quantity diverged: not a verdict, not a first-rejecting gate,
not a layer result, not a count, not a co-failure cell, not a baseline false
allow, not a corpus hash, not a source hash, not a point estimate, not a
bootstrap lower bound.

## 6. Environment delta actually exercised

| | Host | Container |
| --- | --- | --- |
| Distribution | Ubuntu 24.04 userland | Debian 13 (trixie) |
| CPython | 3.12.3, built with GCC 13.3.0 | 3.12.13, built with GCC 14.2.0 |
| glibc | 2.39 | 2.41 |
| SQLite (`sqlite3` module) | 3.45.1 | 3.46.1 |
| NumPy | 2.5.0 | 2.5.0 (same wheel) |
| cryptography | 49.0.0 | 49.0.0 (same wheel) |
| Kernel | 6.8.0-136-generic | 6.8.0-136-generic (**shared**) |
| CPU | same physical host | same physical host |

So the interpreter patch level, the compiler that built it, the C library and
the SQLite engine all changed, and the results did not. The NumPy and OpenSSL
binaries did **not** change.

The SQLite change is worth naming because all three laboratories run a
relational oracle through the stdlib `sqlite3` module: `oracle.sql`,
`oracle_delegation_paths.sql` and the two `run_sql_oracle.py` drivers produced
byte-identical `verdicts.jsonl` and `summary.json` under SQLite 3.46.1 as
under 3.45.1. That is a real, if narrow, robustness observation about the
oracle. It remains, as the packet already says, a second composition code
path over layer results produced by the Python evaluator — **not**
independent validation.

## 7. SAFE bootstrap lower bounds

The review flagged that the percentile of a PCG64 stream can move in the
third decimal across NumPy builds, and that the `n=18` boundary fixture's
decision turns on that.

### 7.1 What the pinned reproduction measured

Container values, read out of
`composed-transaction-corpus/results/verdicts.jsonl`:

| Fixture | n | point estimate | LCB (α=0.05) | threshold | result |
| --- | ---: | --- | --- | ---: | --- |
| `measurement_point_only` | 18 | `0.7645366504492257` | `0.73208839734107` | 0.75 | `FAIL_LCB` |
| `measurement_supported` | 30 | `0.8253772595808534` | `0.8115536419585401` | 0.75 | `PASS` |
| `measurement_profile_mismatch` | 30 | `0.8253772595808534` | `0.8115536419585401` | 0.75 | `PROFILE_MISMATCH` |
| `measurement_unsupported` | 30 | `0.6822630893412698` | `0.6658736155424182` | 0.75 | `FAIL_POINT` |

Every value is **bit-identical** to the host, to the last digit of the repr.
No LCB moved. **No PASS/FAIL_LCB decision changed.** There are no old-versus-new
values to report, because nothing became new.

This is a weak test of the review's concern and should be labelled as such:
the container installed the *same* NumPy 2.5.0 manylinux wheel the host has
installed (§3), so the compiled kernels — including the SIMD-dispatched
`np.mean` reduction that is the plausible source of cross-build drift — were
byte-identical. Identical binaries producing identical floats is close to
tautological.

### 7.2 The margin, so the decision's fragility is a number and not a feeling

For the `n=18` fixture inside this packet the FAIL_LCB decision is not
knife-edge:

```
threshold - lcb = 0.75 - 0.73208839734107 = 0.01791160265893
```

A third-decimal perturbation (±0.001) is an order of magnitude short of
flipping `FAIL_LCB` to `PASS`. Within the V4 packet, the review's stated
failure mode cannot be triggered by a third-decimal move; it would take a
~1.8×10⁻² move.

The genuinely tight decision built on the same `n=18` bootstrap lives in the
**v3** SAFE laboratory, not in this packet — `results/overlap-result.json`,
where `decision_differs` requires
`joint_lcb < 0.737 <= independence_assumed_lcb`:

```
0.737 - joint_lcb                 = 0.737 - 0.73208839734107   = 0.00491160265893
independence_assumed_lcb - 0.737  = 0.7407809858600979 - 0.737 = 0.0037809858600979
```

Both margins are under 5×10⁻³, so *that* decision is third-decimal sensitive.
It is out of scope for the V4 result set, but since it is fed by the same
bootstrap the review was asking about, it was measured too (§7.3) rather than
left as an open worry.

### 7.3 Secondary sensitivity probe — different NumPy builds

Not part of the reproduction verdict. Scripts:
`repro/numpy-sensitivity-probe.sh`, `repro/Dockerfile.numpy-probe`,
`repro/probe-entry.sh`. Each probe image is identical to the reproduction
image except for the NumPy release; each ran with `--network=none`; all
wheels came from the local pip cache.

`composed-transaction-corpus` under four distinct NumPy releases (four
distinct compiled wheels):

| NumPy | `measurement_point_only` LCB | decision | `results/verdicts.jsonl` SHA-256 | `results/summary.json` SHA-256 |
| --- | --- | --- | --- | --- |
| 2.4.4 | `0.73208839734107` | `FAIL_LCB` | `a942d653…cb0d1378` | `ff0ef1d9…3265157f` |
| 2.4.6 | `0.73208839734107` | `FAIL_LCB` | `a942d653…cb0d1378` | `ff0ef1d9…3265157f` |
| **2.5.0 (pinned)** | `0.73208839734107` | `FAIL_LCB` | `a942d653…cb0d1378` | `ff0ef1d9…3265157f` |
| 2.5.1 | `0.73208839734107` | `FAIL_LCB` | `a942d653…cb0d1378` | `ff0ef1d9…3265157f` |

All four LCBs for all four fixtures were bit-identical to the host, and both
substantive result files hashed identically to the host in every case.

The v3 SAFE overlap decision was measured under NumPy 2.5.0 and 2.4.4:
`overlap-result.json` hashed `ccee0a3b…04ead4b8` in both, matching the host —
`joint_lcb = 0.73208839734107`, `independence_assumed_lcb = 0.7407809858600979`,
`decision_differs = true`, unchanged.

**One real cross-build float divergence was found, and it is worth recording
because it is the only one.** Under NumPy 2.4.4 and 2.4.6 the v3 SAFE
`build_corpus.py` regenerates `corpus.json` with a different hash
(`e3d9cfb3…70c4d308`) than the host's (`e5a09eab…1b253689`, reproduced exactly under
2.5.0 and 2.5.1). A structural diff shows **8 last-place (1 ULP) differences**
in generated dataset values, e.g.

```
/datasets/supported[0][2]:   0.8794408930237488 -> 0.8794408930237487
/datasets/unsupported[2][0]: 0.4631245074158415 -> 0.46312450741584155
```

Every substantive value in the v3 SAFE `summary.json` was unchanged under
those versions (`checks 15/15`, `formula_values`, `overlap_decision_differs`,
`point_only_false_allows: 2`, `measurement_fixture_matches: 4`), and the V4
result files were unaffected because the V4 entry points consume the packaged
v3 corpus rather than regenerating it. So: cross-build float drift in this
code base is real and is at the 1-ULP level in corpus *generation*; at the
5000-replicate bootstrap percentile it did not appear at all across four
NumPy releases.

Honest limits on the probe. Four releases on one CPU is not "NumPy builds" in
general: SIMD kernel selection depends on the runtime CPU, and every probe ran
on the same processor. A different microarchitecture, a differently
`-march`-tuned build, or a different BLAS/threading configuration could still
move a reduction. The claim supported is narrow: **on this CPU, across NumPy
2.4.4 / 2.4.6 / 2.5.0 / 2.5.1, the SAFE bootstrap lower bounds did not move at
all** — not in the third decimal, not in the last.

## 8. Verdict

> **Cross-environment reproduction PASS for 23 of the 27 V4 result files
> byte-for-byte, plus all 4 corpus artefacts; the 4 divergent files carry no
> experimental content.** The two `results/run-metadata.json` files differ in
> exactly two keys, `python` and `platform`, which those files exist to
> record; the two `results/SHA256SUMS` files differ in exactly the one line
> that hashes `run-metadata.json`. Every experimental quantity — verdict,
> first-rejecting gate, layer result, count, co-failure cell, baseline false
> allow, corpus hash, source hash, point estimate and bootstrap lower bound —
> reproduced bit-identically under a different Linux distribution, a
> different CPython patch level built by a different compiler, a different
> glibc and a different SQLite. **No PASS/FAIL_LCB decision changed and no
> LCB moved.** This was one container on the same kernel, the same
> x86-64 host and the same CPU, using the same NumPy and OpenSSL binaries as
> the host; it is therefore evidence of cross-environment reproducibility
> only, and not of host, architecture, CPU-dispatch or compiled-dependency
> independence.

And, for C-25 specifically:

> The no-network property of this execution is now measured rather than
> asserted: `--network=none` on both build and run left the namespace with
> `lo` only, no routes, and an outbound TCP connect failing `ENETUNREACH`
> before any laboratory code ran. The `network_used: false` key inside the
> `run-metadata.json` files is still written unconditionally by the runners
> and is still only a declaration; this document, not that key, is the
> evidence.

---

## 9. Files

| Path | Role |
| --- | --- |
| `repro/Dockerfile` | reproduction image, base pinned by digest, offline `pip install` |
| `repro/requirements.txt` | `==` pins with provenance for each |
| `repro/run-in-container.sh` | stages wheelhouse, builds with `--network=none`, runs with `--network=none` and read-only mounts, prints all result hashes |
| `repro/container-entry.sh` | in-container driver: environment dump, network measurement, three entry points, hashes, LCB read-out |
| `repro/collect-wheels.py` | offline wheelhouse builder (local pip HTTP cache → wheelhouse) |
| `repro/Dockerfile.numpy-probe`, `repro/probe-entry.sh`, `repro/numpy-sensitivity-probe.sh` | §7.3 secondary probe only — not part of the verdict |
| `repro/CONTAINER-REPRODUCTION-2026-07-27.md` | this record |

No file under `labs/` was created, modified or deleted by this experiment; the
31 host artefacts were re-hashed after the run and are unchanged. No
`__pycache__` was created on the host by this work (`PYTHONDONTWRITEBYTECODE=1`
in the image; the host interpreter was used only for `collect-wheels.py`,
which imports nothing local). No `SHA256SUMS` under `labs/` was regenerated,
because no result changed.
