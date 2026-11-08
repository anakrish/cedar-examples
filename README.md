# OOPSLA 2024 Cedar/OPA timing reproduction

This branch tests how native-input conversion and reusable graph preprocessing
affect the Cedar/OPA comparison in the original OOPSLA 2024 artifact. It is an
independent reproduction, not an author-endorsed correction or a claim about all
Cedar/Rego workloads.

The starting point is upstream
[`979b9a8`](https://github.com/cedar-policy/cedar-examples/tree/979b9a8ef0d99947f868a5080c4c20a1055a3b51/oopsla2024-benchmarks).
The [original benchmark README](oopsla2024-benchmarks/README.md), generators,
original policies and historical request translations are retained. Cedar and
its generators are pinned to **3.0.1 / `f739ac2`**; OPA is pinned to **0.61.0**.
Dependency locks are reconstructed and committed, not claimed to be the authors'
original lockfiles.

## Reproduce from one checkout

Docker is the only host dependency besides Git. The container pins Rust 1.97.1
and Go 1.26.5; these are **not** the paper's original toolchains. Commands build
the image, obtain the frozen corpus, verify its checksums, replay requests and
produce validated tables, plots and raw measurements.
Base images are digest-pinned. Debian packages installed during image construction
are not snapshot-pinned; Python/library versions and binary hashes are recorded.

```bash
git clone --branch oopsla2024-timing-reproduction \
  https://github.com/anakrish/cedar-examples.git cedar-timing-reproduction
cd cedar-timing-reproduction

# Quick correctness/integration check; not publication-grade measurements.
./reproduce.sh --smoke

# All applications and comparison cases; three repeated measurements.
./reproduce.sh --full

# Select an application without changing its saved workloads.
./reproduce.sh --full --app github

# Reproduce an individual case, always with Cedar as a paired control.
./reproduce.sh --full --app github --case original
./reproduce.sh --full --app github --case input-excluded
./reproduce.sh --full --app github --case closure-prepared
```

For immutable code and corpus provenance, check out the
`oopsla2024-timing-reproduction-v1` release tag instead of the moving branch.
All cases are available at that tag; checking out intermediate commits is only
necessary to inspect how the experiments were introduced.

## Comparisons and timing boundaries

| Case | Original Rego policies? | Authorization timer | Outside authorization timer |
| --- | --- | --- | --- |
| `original` | Yes | OPA `EvalInput` + query evaluation | Query compilation |
| `input-excluded` | Yes | OPA `EvalParsedInput` + query evaluation | Query compilation and native AST input conversion |
| `closure-prepared` | No: separate prepared policies, validated on the corpus | OPA `EvalParsedInput` + prepared-policy evaluation | Native conversion, graph preprocessing and compilation |
| Cedar control | Original Cedar policies | Original `is_authorized()` call | Native requests, entities, transitive closure and policies |

All OPA cases retain the full graph fields. GDrive preprocessing uses the full
datastore principal population, not principals sampled from authorization
requests. Preprocessing happens once per datastore and never inside the
authorization timer. Its cost, query compilation, batch input conversion and
Cedar engine construction are reported in `setup.csv`.

Those setup measurements are **not a complete end-to-end cost accounting**:
generation, Rust-side payload packing, JSON serialization/decoding and IPC are
outside these authorization timers and are not all separately instrumented.
Original OPA conversion is part of evaluation timing, so its separately measured
conversion column is unavailable, not zero.

Default `--timing precise` retains fractional-microsecond samples and uses exact
interpolated empirical quantiles. Engine order rotates across repetitions;
there is no explicit warmup. The paper-style aggregate is the arithmetic mean
of per-size OPA medians divided by the arithmetic mean of per-size Cedar medians,
not the mean of per-size ratios.

To retain original integer-microsecond truncation, approximate quantiles and
fixed engine order:

```bash
./reproduce.sh --full --timing historical
```

Historical timing boundaries and aggregation are preserved, but corpus replay,
raw-sample recording, current hardware and reconstructed builds mean this is
not a bit-for-bit reproduction of the authors' execution environment.

## Workloads and frozen corpora

Full runs use the original seven sizes **5, 10, 15, 20, 30, 40, 50 entities per
type**, with **200 datastores x 500 requests** per size/application. There is no
size-selection option in the runner. Smoke runs retain the sizes but use
2 datastores x 10 requests.

`paper-v1` and `smoke-v1` are frozen corpora distributed as release assets, with
archive and manifest hashes in [corpora.json](reproduction/corpora.json). They
are new samples from the original generators, **not the authors' original
random inputs**. Every case replays the same saved schema-generation bytes,
entities, template links and complete requests, including contexts.
Application selection filters this corpus; it does not regenerate inputs.

To generate an independent corpus, give it a new name explicitly:

```bash
./reproduce.sh --full --generate-corpus --corpus independent-paper-1
```

Generation always includes all three applications so later subset selections
remain comparable. Existing corpora are verified and reused, never overwritten.
Different corpus names represent different randomly generated workloads.

## Outputs and interpretation

### Reference measurement

The published full run uses `paper-v1`, precise timing and three repetitions of
all applications/cases. It validated **6,300,000 shared requests / 25,200,000
engine decisions**, with zero decision mismatches or authorization errors.
Measurement source: [`af64f93`](https://github.com/anakrish/cedar-examples/commit/af64f9303d8f6e7f2bb955cd5dfa32bec3a9548f).

| Application | Original OPA / Cedar | Input-excluded OPA / Cedar | Closure-prepared OPA / Cedar |
| --- | ---: | ---: | ---: |
| GitHub | 83.18x | 15.81x | 5.01x |
| GDrive | 58.69x | 9.57x | 6.45x |
| TinyTodo | 38.61x | 10.12x | 6.52x |

Excluding native-input conversion, without changing the original policies,
reduces measured OPA authorization time by 3.82-6.13x in this run. This shows
the comparison's sensitivity to the timing boundary; it does not show OPA
outperforming Cedar or establish a general result across workloads.
Closure preparation is a separate policy/preprocessing experiment, not a
timing-only correction.

The [release](https://github.com/anakrish/cedar-examples/releases/tag/oopsla2024-timing-reproduction-v1)
contains frozen corpora, the [plot](https://github.com/anakrish/cedar-examples/releases/download/oopsla2024-timing-reproduction-v1/comparison.png),
tables, the complete measurement manifest and compressed raw results.
Observed per-repetition ranges are in the tables, not confidence intervals.
Precise and historical smoke checks also pass; no full historical-mode
measurement is claimed.

### Generated artifacts

Each invocation creates a fresh directory under `reproduction/results/`:

- `summary.csv`: average medians, OPA/Cedar ratios and observed min/max ratios
  across repeated runs. These ranges are not confidence intervals.
- `per-repetition.csv`, per-application/per-size CSVs and comparison PNG/PDFs.
- Compressed per-request samples with datastore/request identifiers and actual
  nanosecond timings, plus `setup.csv` and execution logs.
- `manifest.json`: exact commands in the logs, source revision/hashes, corpus
  hash, binaries, toolchains, CPU information, configuration and validated counts.

A run is marked complete only after all expected requests are present, every
engine agrees with Cedar, no authorization errors occur, setup records are
present and precise medians match raw samples. Failures retain incomplete
manifests and logs. Full all-case runs validate 2.1 million shared requests per
repetition, with four engine decisions per request.

The container is limited to 4 CPUs and 8 GiB; it does not isolate the physical
host. Run on an otherwise idle machine and compare repeated runs. Exact timings
will vary by hardware and scheduling. The larger 100-500 scaling experiments,
updated workload fixes and RVM comparisons are deliberately outside this initial
correction-focused branch.

## Native execution and tests

For development, with compatible Rust/Go, Python, matplotlib and pandas already
installed, put `--native` first:

```bash
./reproduce.sh --native --smoke
cd oopsla2024-benchmarks
cargo test --locked -j 4
cargo fmt --check
(cd tinytodo/rego && go test ./... && go vet ./...)
cd ..
python3 -m unittest discover -s reproduction
```

The original upstream Dockerfile remains unchanged; use the root runner and
`reproduction/Dockerfile` for the pinned Cedar/OPA-only environment.

## License

This project is licensed under the Apache-2.0 License.
