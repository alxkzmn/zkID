# Verifier extraction baseline

Capture a reproducible baseline for `ecdsa_spartan2::prover::verify_linked` without changing the verifier, dependency lockfile, or pinned tools. This records Rust tests, Charon extraction, and the subsequent Aeneas Lean translation attempt. Cryptographic operations remain opaque; these artifacts establish neither cryptographic correctness nor an OpenAC proof.

## Run

Use the prepared cloud environment with `/workspace/formal-tools/env.sh` and its pinned Rust, hax, Charon, Aeneas, and Lean installations. The Bash runner sources that environment automatically and resolves the repository root independently of the caller's working directory.

From the repository root:

```sh
bash verification/ecdsa-spartan2/baseline/run.sh
# Or choose a new output directory:
bash verification/ecdsa-spartan2/baseline/run.sh /tmp/openac-baseline-fresh
```

The optional output path must not already exist. By default, the runner creates an ignored directory under `baseline/runs/`, named `baseline-<UTC timestamp>-<random suffix>`. The committed fresh-run evidence is in [`artifacts/`](artifacts/).

The Rust stage uses `cargo test --locked --lib --no-default-features -- --nocapture`. Disabling default features excludes native witness generation. Native tests and Charon's Miri extraction use separate target directories. Source and lockfile identities are retained in the evidence.

The Aeneas stage uses fresh LLBC and Lean output paths with this invocation:

```text
aeneas -backend lean -core-models-lib -split-files -specs hax -dest FRESH_LEAN FRESH_LLBC
```

After a complete evidence capture, the runner exits `1` when a recorded pipeline stage fails, including the expected Aeneas translation error. Incomplete collection, infrastructure failures, or identity drift stop the runner with exit `2`. Consult `metadata.json` for completed-capture status and each stage's actual exit status. A completed evidence capture does not mean the translation succeeded.

## Recorded result

The fresh run targets unchanged source commit `b395e09c225ff45b003f0087c28e2e208e22f944`.

| Stage | Exit status | Observed result |
| --- | --- | --- |
| Dependency metadata | 0 | Root feature set empty; `native-witness` disabled |
| Resolved dependency integrity, before/after | 0 | Spartan2 checkout and halo2curves package content verified; no Cargo source/patch/path overrides |
| Rust library tests | 0 | 14 reported passes; three `.sym`-dependent early returns, 11 exercised tests |
| Charon | 0 | `has_errors=false`; exactly one structured `verify_linked` declaration |
| Coverage validation | 0 | 619 serialized LLBC function declarations: 2 structured, 617 opaque, 0 other |
| Aeneas | 2 | Mixed trait/type group rejected; no Lean files generated |
| Coverage/group summary | 0 | Fresh coverage and actual rejected declarations recorded |
| Harness | 1 | Evidence capture complete; pipeline failed |

The serialized structured bodies are `verify_linked` and tuple drop glue. Spartan2's
cryptographic `verify` declaration is opaque; the target contains two direct
syntactic calls to that declaration. The first rejected group is
`halo2curves::curve::{CurveExt, CurveAffine, Coordinates}`; see
[`declaration-groups.txt`](artifacts/declaration-groups.txt) and the complete
cleaned [`aeneas.log`](artifacts/aeneas.log).

The early-return tests are
`utils::issuer_key_layout_tests::{public_io_indices_match_jwt_sym, public_io_indices_match_mdoc_sym}`
and `utils::show_witness_indices_tests::witness_indices_match_show_sym`.
The runner's reported pass count includes these early returns.

These are counts of serialized LLBC function declarations. Charon can retain
auxiliary declarations for pretty printing, so the totals are not exact
reachable-body or runtime coverage. The actual opaque Spartan verification
declaration is identified separately in the summaries.

## Evidence and scope

| Files | Contents |
| --- | --- |
| `metadata.json`, `commands.txt` | Run provenance, exact commands, stage statuses, and capture status |
| `tool-identities.json`, `dependencies.json`, `source-hashes.json` | Tool, dependency, source, and lockfile identities |
| `dependency-integrity.json`, `spartan2-files.sha256`, `halo2curves-files.sha256` | Actual resolved source paths/content and applicable Cargo configuration checks |
| `rust-tests.log` | Actual test output, including artifact-dependent early returns |
| `charon.log`, `ecdsa_spartan2.llbc.gz` | Extraction diagnostics and compressed LLBC |
| `coverage.json`, `coverage.txt`, `declaration-groups.txt` | Structured versus opaque declarations and dependency groups |
| `aeneas.log` | Actual Lean translation diagnostics |
| `SHA256SUMS` | Checksums for retained evidence |

Verify the retained files from their output directory with `sha256sum -c SHA256SUMS`. Rust's reported passing-test count includes tests that return early when compiled Circom `.sym` files are absent; use the log and recorded counts to distinguish exercised tests from those early returns. The library test selection excludes integration tests and does not exercise dedicated `verify_linked` proof fixtures.

The known translation blocker is the mixed declaration group containing `halo2curves::CurveExt`, `CurveAffine`, and `Coordinates`. Extraction coverage matters independently: successfully translating a wrapper with opaque foreign verification calls would still leave concrete cryptographic correctness unproved.

The integrity check verifies Spartan2's resolved checkout HEAD and tracked
content, and compares installed halo2curves files with the cached published
crate after checking that archive's SHA-256 against `Cargo.lock`. Applicable
Cargo configuration and manifests are inspected for source, patch, replacement,
or path overrides without recording credentials. Unexpected overrides or dirty
inputs stop collection; inputs are checked again after the run.

## Historical command provenance

The Aeneas invocation above was recovered from setup chat `01a1c5b6-42f2-76ee-9f7c-5d19041ec0bc`, command `exec-21ae7c86-31e8-406b-9d98-fc06cdc61ac0`. It produced `openac-aeneas-hax-models.log`, copied into the retained archive as `aeneas-translation-failure.log`. This baseline replays that exact option set with fresh paths. The earlier `openac-aeneas.log` attempt omitted `-core-models-lib -specs hax`; that variant is not replayed here. The historical numeric exit status was not retained; the fresh exit status is recorded directly.

This baseline introduces no tool upgrades, dependency forks, or application fixes. Fresh results are recorded in `artifacts/metadata.json` and the corresponding logs.
