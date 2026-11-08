# Current-upstream Cedar/OPA timing comparison

This branch ports our paired timing experiments onto upstream
[`release/4.14.x` at `f4d2dbb`](https://github.com/cedar-policy/cedar-examples/tree/f4d2dbbab361a38372e6d6fcfc7b777eb1b30c37/oopsla2024-benchmarks).
It is a current-engine comparison, **not a reproduction of paper-era timings**.
The historical [reproduction release](https://github.com/anakrish/cedar-examples/releases/tag/oopsla2024-timing-reproduction-v1)
remains unchanged.

## Run

```bash
git clone --branch upstream-timing-comparison \
  https://github.com/anakrish/cedar-examples.git cedar-upstream-timing
cd cedar-upstream-timing
./reproduce.sh --smoke
./reproduce.sh --full
./reproduce.sh --full --app github
./reproduce.sh --full --app github --case input-excluded
./reproduce.sh --smoke --timing historical
```

Git and Docker are the host requirements. The first run generates a corpus from
the pinned current generators for all three applications; later runs verify and
reuse it. Cases replay identical schema bytes, entities, links and requests.
Corpora from the historical branch are not silently reused. For an additional
independent corpus, use `--generate-corpus --corpus independent-1`.
Corpus manifests bind the checksummed inputs to the pinned dependency revisions;
inputs generated with other revisions are rejected, not silently regenerated.

Full settings retain sizes **5,10,15,20,30,40,50**, with 200 datastores and
500 requests per size/application. Smoke retains those sizes with 2 datastores
and 10 requests. Full runs default to three repetitions; smoke defaults to one.
There is no root-runner size option.

## Pins and experiments

[versions.json](reproduction/versions.json) pins Cedar **4.14.0** source
`5af7b8c`, spec/generators `a4c5a89`, and OPA **1.22.2**. Dependency preparation
checks exact, clean source revisions rather than following moving branches.
Cargo and Go dependency locks are committed. Rust 1.97.1 and Go 1.26.5 base
images are digest-pinned; Debian packages are not snapshot-pinned.

| Case | Policy | Authorization timer |
| --- | --- | --- |
| `original` | Unchanged upstream Rego | `EvalInput` plus query evaluation |
| `input-excluded` | Unchanged upstream Rego | `EvalParsedInput` plus query evaluation |
| `closure-prepared` | Separate prepared Rego | `EvalParsedInput` plus prepared evaluation |
| Cedar control | Unchanged upstream Cedar | `is_authorized()` |

OPA uses explicit Rego v0 compatibility for the unchanged upstream policies
and separate prepared policies. This does not silently upgrade their syntax.
Current generator APIs require compatibility updates: removed settings use the
current type-directed defaults, while supported workload settings are preserved.
These inputs are therefore not asserted to be identical to paper-era inputs.
Input conversion is outside the timer in the latter two OPA cases; graph
preprocessing is once per datastore in the prepared case. Full graph fields
and request translations are retained. GDrive preparation covers all datastore
principals, not just those appearing in sampled requests.

`setup.csv` reports Cedar construction, OPA compilation, conversion and
preprocessing. These are **partial setup costs**, not complete end-to-end
accounting: generation, payload packing, serialization and IPC are not all
separately instrumented.

Default precise timing preserves fractional microseconds and exact empirical
quantiles, rotating engine order between repetitions. Historical mode retains
integer-microsecond truncation, approximate quantiles and fixed order. Neither
mode has explicit warmup. Ratios divide the arithmetic mean of per-size OPA
medians by the arithmetic mean of per-size Cedar medians.

## Validation and outputs

Each run creates a new `reproduction/results/` directory with summaries,
per-repetition tables, plots, compressed raw measurements, setup records,
logs and a source/corpus/binary/environment manifest. Completion requires
all expected decisions, no errors or decision mismatches, complete setup
records, and precise medians matching raw samples. Failed runs retain logs.
Prepared-policy agreement is validated on the corpus, not a universal
equivalence proof. The Docker runtime uses 4 CPUs / 8 GiB on a shared host;
timings vary with hardware and scheduling. No full current-engine performance
measurement is claimed merely from smoke validation.

Validated with the pinned Docker image: three precise all-case repetitions
(5,040 decisions), one historical all-case repetition (1,680), and a selected
GitHub/input-excluded run (280), with zero mismatches or authorization errors.
Native all-case smoke and Rust, Go and Python regression checks also pass.

For native development, install compatible Rust/Go/Python and matplotlib/pandas,
then use `./reproduce.sh --native --smoke`. Tests:

```bash
python3 reproduction/dependencies.py
(cd oopsla2024-benchmarks && cargo test --locked -j4 && cargo fmt --check)
(cd oopsla2024-benchmarks/rego-harness && go test ./... && go vet ./...)
python3 -m unittest discover -s reproduction
```

Upstream's [benchmark README](oopsla2024-benchmarks/README.md) and original
Dockerfile are preserved; use the root runner for this pinned experiment.

## License

Apache-2.0.
