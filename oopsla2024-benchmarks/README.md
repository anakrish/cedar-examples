# OOPSLA 2024 benchmarks for Cedar

This folder contains the Cedar, Rego and OpenFGA policies, along with benchmarking code and scripts, used for the performance evaluation of the [OOPSLA2024 paper on Cedar](https://dl.acm.org/doi/10.1145/3649835).
For the exact version used in the paper, use the `release/3.1.x` branch.

## Cedar versus Regorus interpreter and RVM

The cross-engine harness remains upstream in
[`cedar-policy/cedar-examples`](https://github.com/cedar-policy/cedar-examples/tree/main/oopsla2024-benchmarks).
The newer [`cedar-spec/cedar-benchmarking`](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-benchmarking)
also includes an OOPSLA corpus, but benchmarks Cedar operations only; it is not
a relocation of this cross-engine harness. The examples default branch is
`release/4.14.x`; its benchmark directory currently matches `main`.

The fork's Regorus changes are on `release/3.1.x-rego-tweaks`,
`release/3.1.x-rego-precompute`, `release/3.1.x-rego-precompute-opt`, and
`release/3.1.x-rego-precompute-opt-large`. This port starts from upstream
`main` (`268c561`) and carries forward the last branch's policy optimizations.
Cedar is pinned to latest `main` at `062c8fe71016723883b3ae31298720363a1e14c8`
(its manifest reports 4.14.0; the separate latest release tag is 4.14.1),
the generators are at cedar-spec `ac201c127d31cff4bea784c87d3e3d3e8fb8bfe9`,
and Regorus is pinned to upstream `1423851f608e2ca809727fa32c54a8d46c297c08`
(six commits after the latest release, 0.14.1). `Cargo.lock` pins Rust dependencies.

For a native run, install Rust, a C/C++ toolchain, OpenSSL development headers,
and Python 3 with matplotlib and pandas. From this directory:

```shell
git clone https://github.com/cedar-policy/cedar-spec --depth 1
git -C cedar-spec fetch origin ac201c127d31cff4bea784c87d3e3d3e8fb8bfe9 --depth 1
git -C cedar-spec checkout ac201c127d31cff4bea784c87d3e3d3e8fb8bfe9
git clone https://github.com/cedar-policy/cedar cedar-spec/cedar --depth 1
git -C cedar-spec/cedar fetch origin 062c8fe71016723883b3ae31298720363a1e14c8 --depth 1
git -C cedar-spec/cedar checkout 062c8fe71016723883b3ae31298720363a1e14c8
bash reproduce.sh
```

For a quicker run, use
`NUM_HIERARCHIES=20 NUM_REQUESTS=200 bash reproduce.sh`.
The script runs GitHub only: first Cedar versus the Regorus interpreter,
then a separate Cedar versus Regorus RVM run. No Pre-TC variants are selected.
Override `NUM_ENTITIES` with comma-separated sizes to test larger hierarchies.
Existing result directories are never overwritten. Set `OUTPUT_ROOT` to a new
directory for another run; the CLI likewise requires a fresh `--output-dir`.
The default uses the paper's 200 hierarchies, 500 requests per hierarchy,
and seven hierarchy sizes for GitHub. Within each comparison, both engines
see identical generated requests and must agree on every decision. The two
comparisons generate independent random workloads; each has its own Cedar
baseline. Results are not bitwise reproducible.

`--engine` accepts `regorus`, `regorus-pre-tc`, `regorus-rvm`, and
`regorus-rvm-pre-tc`. Unlike the old fork, the Pre-TC choices actually build
closed Cedar entity graphs. GitHub always precomputes its capability and action
closures, as in the optimized fork. Both Regorus backends run the same policy.
The existing OPA policies are unchanged.

The fork's `else` encodings produced incorrect RVM denials for GitHub owner
permissions and TinyTodo transitive permissions, on both release 0.14.1 and
the pinned upstream revision. The benchmark policies therefore express the
same alternatives using one existential GitHub rule and independent TinyTodo
rules instead. Tests cover these permission cases and per-request VM resets.
This is a policy encoding change, not a fix to Regorus itself.

Measurements include input installation and evaluation, but exclude JSON
conversion, entity closure construction, Rego preprocessing, policy parsing,
RVM compilation, and one warm-up per Cedar/Regorus instance. GDrive conversion
includes materializing view-access sets from the closed entity graph. They
measure prepared-data steady-state authorization, not cold-start or end-to-end
costs. Durations retain sub-microsecond precision.

Following review, engine execution order rotates across hierarchies, so a
two-engine run with 200 hierarchies runs each engine first 100 times. Both
engines complete their request batch before report aggregation. Median, p90,
and p99 are exact empirical quantiles, linearly interpolated at `q * (n - 1)`,
instead of the original harness's approximate streaming P2 estimates. Samples
are pooled across hierarchies at each size; an "average median" is an arithmetic
average of those per-size medians, not an overall request median. These are
intentional measurement-control changes, separate from policy optimizations.
Execution remains sequential on a shared machine without CPU isolation,
repeated independent runs, or statistical confidence intervals.

Each comparison has its own CSV, benchmark log, run manifest, and machine/source
provenance. `source.tar.gz` archives the harness sources and policies, including
uncommitted edits. Complete harness/dependency source checksums, dependency
revisions and dirty diffs, and the executable checksum identify the measured
implementation; reproducing dirty dependency checkouts additionally requires
their matching source state. The manifest records sample settings, measurement
controls, completion, and the source archive fingerprint.

The original GitHub results remain at:

* `output/cedar-vs-regorus/`: Cedar versus the Regorus interpreter.
* `output/cedar-vs-regorus-rvm/`: Cedar versus Regorus RVM.

Timing plots show median and p99, and are named
`github/times_vs_num_entities.pdf` (or `.png`) within each comparison directory.
The CLI also supports `--output-dir` for keeping other runs separate.

### Prepared GDrive and TinyTodo policies

The same prepare-once pattern is used for these workloads. GDrive prepares
per-principal view, owned-document, and owned-folder capability sets, including
folder descendants, plus an action-to-capability map. Preparation covers every
User in the hierarchy, independently of the future request batch; it does not
precompute request decisions. TinyTodo prepares group transitive closure and action-to-permission
maps. Their timed policies still select the action and check membership or
ownership. Both backends use the same prepared policy and data.

To compare only Cedar and RVM on these two workloads without overwriting the
GitHub results:

```shell
APPS=gdrive,tiny-todo BACKENDS=regorus-rvm \
  OUTPUT_ROOT=output/optimized-other \
  NUM_HIERARCHIES=30 NUM_REQUESTS=300 NUM_ENTITIES=5,10,20,30,50 \
  bash reproduce.sh
```

`APPS`, `BACKENDS`, and `NUM_ENTITIES` accept comma-separated values.
RVM runs log `regorus_setup` records per hierarchy: `preprocessing_us` measures
the Rego preprocessing query and loading its result; `compilation_us` measures
compilation and VM program/data loading. Neither includes JSON conversion,
policy parsing, or warm-up. These costs are not part of the authorization
latency plots. Cedar's entity construction and transitive closure also happen
outside its authorization timer, but their setup costs are not measured here.
All these are steady-state comparisons, not end-to-end startup measurements.

### Figure 14-style Cedar versus RVM comparison

[Figure 14 of the paper](https://arxiv.org/pdf/2403.04651) is the appropriate
reference: it compares authorization scaling across GDrive, GitHub, and
TinyTodo. Figure 15 instead evaluates Cedar templates and policy slicing.

```shell
APPS=gdrive,github,tiny-todo BACKENDS=regorus-rvm \
  OUTPUT_ROOT=output/figure14-reviewed-2026-11-03 \
  NUM_HIERARCHIES=200 NUM_REQUESTS=500 \
  NUM_ENTITIES=5,10,15,20,30,40,50 \
  bash reproduce.sh
```

Each plotted point contains 100,000 measured requests, or 700,000 per application
and 2.1 million across all three. Within each point, both engines receive the
same requests and must agree on every decision. The combined plot uses the
paper's panel order, median/p99 curves, microsecond units, and independent
zero-based linear y axes, selecting only Cedar and RVM.

The comparison directory contains `figure14_cedar_vs_rvm.pdf`, `.png`, and
`figure14_cedar_vs_rvm_summary.csv`, in addition to the per-application plots.
Combined plotting validates manifest completion, sample counts, sizes, matching
allow rates, zero evaluation errors, and the archived source fingerprint.
Missing manifests or mixed sample settings are rejected, and obsolete combined
plots are removed rather than left behind.

The published PNG has a presentation caption added after measurement, with its
observed speedup range in bold. Its plotted pixels are unchanged; the original
PNG/PDF and summary are retained under
`output/plot-backups/figure14-reviewed-before-large-2026-11-03T08-00-41/`.
The PDF retains the original vector rendering. `plot.py` reproduces the curves
and original rendering, not the later PNG-only caption. Archived measurement
sources and fingerprints are retained unchanged.

This is not an exact reproduction of the paper's original measurements: engine
versions, hardware, prepared Rego implementations, the controls above, and the
GDrive workload corrections below differ. Language-specific reusable preparation
is allowed, but excluded setup/update/amortization costs prevent interpreting
these latency results as end-to-end performance or intrinsic language speed.

### Reviewed full-run results

The command above completed with 700,000 matching Cedar/RVM decisions per
application, 2.1 million paired requests in total, and zero evaluation errors.
Each CSV contains seven sizes with 100,000 measured requests per engine at
each size. The source fingerprint, manifest, summaries, and combined PDF/PNG
were checked against this fresh run.

| Application | Cedar average median (us) | Prepared RVM average median (us) | Cedar/RVM |
|---|---:|---:|---:|
| GDrive | 3.558 | 1.656 | 2.15x |
| GitHub | 7.454 | 3.694 | 2.02x |
| TinyTodo | 3.725 | 2.004 | 1.86x |

These are averages of per-size medians, with exact quantiles and all four
reviewed measurement controls enabled. The restored GDrive view grants and
all-user preparation are included. Historical pre-review numbers are not a
paired baseline for these measurements.

The 4,200 setup records are retained in `setup-samples.csv`, with summaries by
application/size in `setup-summary.csv` and by application in
`setup-summary-by-app.csv`. Mean Rego-preprocessing/RVM-compilation costs are
1,728/109 us for GDrive, 649/80 us for GitHub, and 211/78 us for TinyTodo.
These are partial setup costs with the exclusions documented above, not total
startup costs or an end-to-end comparison with Cedar.

### Historical results before review fixes

These retained measurements predate the controls above. In particular, the
GDrive workload omitted view-granted access because of two inherited upstream
defects: document/folder View IDs omitted the `user_`/`group_` prefixes, and the
Rego converter searched View ancestors instead of descendants. Both defects
also occur on upstream `release/3.1.x`. Decision agreement alone missed them.
**The GDrive numbers below do not characterize the intended workload and must
not be used as its performance baseline.**

The fixes restore those references and view grants. A deterministic end-to-end
fixture requires private, unowned documents to be readable solely through
direct, group, and folder-inherited view grants, comparing Cedar, the original
Rego policy, and both Regorus backends. TinyTodo also retains direct permissions
when a principal has no group-graph entry, and unsupported-only OPA template runs
continue to skip rather than panic.

The GitHub comparisons use 200 hierarchies and 500 requests at each of seven
sizes. Average medians are 8.35 us Cedar versus 8.10 us interpreter, and,
in the separate RVM run, 7.39 us Cedar versus 3.59 us RVM.

The GDrive/TinyTodo validation uses the command above: 30 hierarchies and
300 requests at each of five sizes, or 45,000 requests per application.

| Application | Cedar average median (us) | Prepared RVM average median (us) | Cedar/RVM |
|---|---:|---:|---:|
| GDrive | 3.552 | 1.568 | 2.27x |
| TinyTodo | 3.604 | 1.327 | 2.72x |

Mean once-per-hierarchy preprocessing/compilation costs are 854/101 us for
GDrive and 170/63 us for TinyTodo. All request decisions matched Cedar with
zero evaluation errors, but did not exercise the missing GDrive view grants.
Unit tests include comparisons against the original
GDrive and TinyTodo Rego policies across all actions, direct/inherited rights,
owners, public access, denials, cycles, and per-request reset behavior.

The pre-optimization baseline is retained locally in `output/baseline-other/`:
RVM average medians were 2.210 us for GDrive and 3.041 us for TinyTodo.
Before/after runs use the same sample settings but independent random workloads;
they are not paired measurements. Optimized CSVs, plots, source/machine
provenance, `comparison-summary.csv`, and setup samples/summaries are under
`output/optimized-other/cedar-vs-regorus-rvm/`. Timing is from one shared
AMD Ryzen 9 8945HX environment, without CPU isolation or confidence intervals.

## Getting started

We recommend you use Docker for benchmarking, as our Dockerfile automatically
pulls in all the necessary dependencies.

1. Build the Docker image with `docker build -t cedar-benchmarks .` from this
directory.
2. Launch the Docker image in interactive mode with `docker run --rm -it cedar-benchmarks`.
3. Inside the Docker image, run `cargo run --release -- help bench`. (Note the
space between `--` and `help`.) This should show the help message (usage
instructions) for our benchmarking CLI. Seeing this message confirms that you
can build Cedar and our benchmarking harness.

## Directory structure

* `benches/`: Cedar, OpenFGA, and Rego policies used for benchmarking. See the README in that folder for more details.
* `generators/`: Python scripts that generate entity data for benchmarking.
* `rego-harness/`: Go wrapper to run Rego.
* `src/`: Rust code that performs the benchmarking. `src/main.rs` is what runs when you run `cargo run --release`.
* `Dockerfile`: Builds the test environment (see instructions above).
* `openfga-timing.patch`: OpenFGA patch to apply to the version used in our experiments.
* `plot.py`: Python script to plot results.
* `validate_all_benchmarks.sh`: Bash script to check that all Cedar policies validate against the provided schemas.

## Running benchmarks with the settings used for the paper

Inside the Docker image (see above), run

```shell
cargo run --release -- bench \
  --app gdrive,github,tiny-todo,gdrive-templates,github-templates \
  --engine cedar,open-fga,rego,cedar-opt \
  --num-hierarchies 200 \
  --num-requests 500 \
  --num-entities 5,10,15,20,30,40,50
```

This repeatedly starts and stops an OpenFGA server, which produces a lot of
repetitive warnings about "authentication is disabled" and "TLS is disabled" as
well as some configuration errors ("config '...' should not be higher than
'...'). These are normal. Warnings about "Exhausted randomness, retrying" are
also part of normal operation.

With the settings above, the command will take perhaps 1-2 hours to complete,
depending on your hardware specs etc.
For faster (but more noisy) results, reduce the `--num-hierarchies` or
`--num-requests` parameters.

When the command finishes, it produces:

* Summary outputs (overall averages) on stdout. These correspond to the overall
averages reported in Section 5 and also in the Introduction of the paper.
* Graphs, in the `output/` subdirectory. View these by using `docker cp` to copy
the container's `/cedar-benchmarks/output` to your local machine. (For instance,
in a separate terminal outside the container,
`docker cp confident_jepsen:/cedar-benchmarks/output ./output`. Replace
`confident_jepsen` with your own running container's name, found using
`docker ps`. Note that if `output` already existed on your local machine, this
will create a new `output` directory inside your existing `output` directory,
which is probably not what you want.)
  * `output/gdrive/times_vs_num_entities.pdf` corresponds to Fig 14a
  * `output/github/times_vs_num_entities.pdf` corresponds to Fig 14b
  * `output/tinytodo/times_vs_num_entities.pdf` corresponds to Fig 14c
  * `output/gdrive-slicing/times_vs_num_entities.pdf` corresponds to Fig 15a
  * `output/github-slicing/times_vs_num_entities.pdf` corresponds to Fig 15b
