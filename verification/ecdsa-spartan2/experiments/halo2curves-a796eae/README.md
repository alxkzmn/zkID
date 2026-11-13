# Pinned halo2curves translation retry

Retry the real `ecdsa_spartan2::prover::verify_linked` extraction with the dependency patch from [`alxkzmn/halo2curves`](https://github.com/alxkzmn/halo2curves/tree/a796eae54af4dda7f672c243a36fd9729d59944e), pinned to commit `a796eae54af4dda7f672c243a36fd9729d59944e`. Compare against baseline commit `cc1955665e58d815950ef8387071af04ae6c4486` and its retained [`baseline/`](../../baseline/) evidence.

The crate's `Cargo.toml` adds exactly one `[patch.crates-io]` entry for that Git URL and revision. `Cargo.lock` changes two package sources from crates.io to the pinned checkout:

| Package | Version | Source change |
| --- | --- | --- |
| `halo2curves` | `0.9.0` | Published registry package to pinned Git fork |
| `halo2derive` | `0.2.0` | Published registry package to the same fork's `derive/` package |

The lockfile was prepared with `cargo update -p halo2curves --precise 0.9.0`.
Input verification rejects any semantic lockfile changes beyond these two source transitions.

The reviewed fork change restructures the curve traits and coordinate API to remove declaration cycles. Its reviewed diff leaves arithmetic implementations unchanged. This API review does not establish formal equivalence or cryptographic correctness.

Application Rust sources, the recorded baseline directory, Spartan2's pinned source, and tool identities remain unchanged. The experiment permits only the audited crate manifest and lockfile differences; it does not relax the baseline harness's source checks.

## Run

Use the prepared cloud environment. The runner sources `/workspace/formal-tools/env.sh` automatically; `OPENAC_FORMAL_ENV` can select an equivalent prepared environment, whose tool identities must match the baseline.

From the repository root:

```sh
bash verification/ecdsa-spartan2/experiments/halo2curves-a796eae/run.sh
# Or select a new, nonexisting output directory:
bash verification/ecdsa-spartan2/experiments/halo2curves-a796eae/run.sh /tmp/openac-halo-patch-fresh
```

The default output is a fresh ignored `runs/retry-<random suffix>` directory beside the runner. Native Rust tests and Charon's Miri extraction use separate target directories. Their defaults reuse the prepared caches; these are not experiment-specific caches. Resolved dependency contents are verified independently before and after the run.

The runner performs real Rust library tests with the same baseline selection:

```text
cargo test --locked --lib --no-default-features -- --nocapture
```

Charon and Aeneas use the baseline option sets with fresh paths:

```text
charon cargo --preset=aeneas --sysroot miri --start-from ecdsa_spartan2::prover::verify_linked --dest-file FRESH_LLBC -- --locked --lib --no-default-features
aeneas -backend lean -core-models-lib -split-files -specs hax -dest FRESH_LEAN FRESH_LLBC
```

Aeneas runs only after successful Charon extraction and structural validation. A complete capture exits `1` if a recorded stage fails; incomplete capture or input/tool identity failures exit `2`. Actual stage exit statuses and any skipped translation stage are recorded rather than treated as success.

## Evidence and interpretation

The output records exact commands, logs, tool identities, source hashes, and the manifest/lockfile diff. `input-integrity.json`, `fork-files.sha256`, and `spartan2-files.sha256` identify the actual resolved fork and unchanged Spartan2 contents. Input validation checks the permitted patch, both resolved Git packages, checkout revision and bytes, applicable Cargo configuration, and source identities before and after execution.

When extraction succeeds, the output also retains compressed LLBC, serialized declaration summaries, direct target callsites, actual rejected declaration groups, and any generated Lean files. `metadata.json` distinguishes evidence-capture status from pipeline status. `SHA256SUMS` covers retained evidence; check it from the output directory with `sha256sum -c SHA256SUMS`.

Declaration totals describe serialized LLBC function declarations, including auxiliary declarations Charon may retain for pretty printing. They do not measure exact reachable-body or runtime coverage. The actual opaque Spartan verification declaration and the target's direct syntactic calls are recorded separately. Rust test logs also distinguish reported passes from artifact-dependent early returns; the library selection excludes integration tests and does not exercise dedicated `verify_linked` proof fixtures.

No translation result is assumed. A cleared declaration cycle would still leave any further translator failures, opaque cryptographic implementations, and proof obligations to assess. Successful Lean generation alone would not establish verifier correctness or commitment soundness.

## Recorded result

The fresh retry clears the original mixed declaration group. Translation still fails; see [`metadata.json`](artifacts/metadata.json), [`coverage.json`](artifacts/coverage.json), and the complete cleaned [`aeneas.log`](artifacts/aeneas.log).

| Check | Baseline | Pinned retry |
| --- | --- | --- |
| Input/tool checks | Original dependencies verified | Pinned tools match; input integrity verified before/after, both exit `0` |
| Rust library tests | 14 reported passes; 3 early returns; 11 exercised | Same counts; exit `0` |
| Charon extraction | Exit `0`; `has_errors=false`; structured target | Same result |
| Serialized LLBC function declarations | 619: 2 structured, 617 opaque | Same counts |
| Direct syntactic calls to opaque Spartan `verify` | 2 | 2 |
| Original `CurveExt`/`CurveAffine`/`Coordinates` mixed group | Rejected | Separate nonrecursive groups in `ordered_decls`; rejection absent from diagnostics |
| Aeneas | Exit `2`; no Lean files | Exit `2`; no Lean files |
| Harness | Exit `1`; capture complete; pipeline failed | Same status |

The retry's first logged internal error concerns Spartan2's `verify` signature. Later, Aeneas explicitly reports unsupported dynamic trait types for `hash_to_curve`, whose return type contains `Box<dyn Fn>`. The run terminates with a further internal error in signature translation's assertion check. The log does not establish dynamic traits as the sole remaining cause. The declaration-cycle fix therefore demonstrates progress past that rejection without establishing successful Lean translation or a correctness proof.
