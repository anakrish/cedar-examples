#!/usr/bin/env python3
import argparse
import csv
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "oopsla2024-benchmarks"
CORPORA = ROOT / "reproduction/corpora"
RESULTS = ROOT / "reproduction/results"
UPSTREAM = "979b9a8ef0d99947f868a5080c4c20a1055a3b51"
RELEASE = "oopsla2024-timing-reproduction-v1"
APPS = ("github", "gdrive", "tinytodo")
SIZES = (5, 10, 15, 20, 30, 40, 50)
CASES = {
    "original": "rego",
    "input-excluded": "rego-input-excluded",
    "closure-prepared": "rego-closure-prepared",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def command_output(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def run_benchmark(binary, arguments, log):
    command = [str(binary), "bench", *map(str, arguments)]
    with log.open("x") as stream:
        stream.write("command " + json.dumps(command) + "\n")
        stream.flush()
        try:
            subprocess.run(command, cwd=BENCH, stdout=stream, stderr=subprocess.STDOUT,
                           env={**os.environ, "MPLBACKEND": "Agg"}, check=True)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(f"benchmark failed; see {log}") from error


def corpus_files(directory):
    return {str(path.relative_to(directory)): sha256(path)
            for path in sorted(directory.rglob("*.json"))
            if path.name != "manifest.json"}


def verify_corpus(directory, preset):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["format_version"] != 1 or manifest["preset"] != preset:
        raise ValueError("corpus format/preset mismatch")
    if manifest["upstream_commit"] != UPSTREAM or manifest["apps"] != list(APPS):
        raise ValueError("corpus provenance/application mismatch")
    if manifest["sizes"] != list(SIZES):
        raise ValueError("corpus does not contain the original seven sizes")
    expected_files = {
        f"{app}/{size}/{name}.json"
        for app in APPS for size in SIZES
        for name in ["metadata", *range(1, manifest["num_hierarchies"] + 1)]
    }
    if set(manifest["files"]) != expected_files or corpus_files(directory) != manifest["files"]:
        raise ValueError("corpus is incomplete or its checksums do not match")
    index_path = ROOT / "reproduction/corpora.json"
    if index_path.exists():
        index = json.loads(index_path.read_text())
        if directory.name in index:
            if sha256(directory / "manifest.json") != index[directory.name]["manifest_sha256"]:
                raise ValueError("corpus does not match the published corpus with this name")
    return manifest


def download_corpus(name):
    index = json.loads((ROOT / "reproduction/corpora.json").read_text())
    if name not in index:
        raise ValueError("unpublished corpus; use --generate-corpus with a new corpus name")
    url = (f"https://github.com/anakrish/cedar-examples/releases/download/"
           f"{RELEASE}/{name}.tar.gz")
    with tempfile.TemporaryDirectory(dir=CORPORA) as temporary:
        temporary = Path(temporary)
        archive = temporary / "corpus.tar.gz"
        with urlopen(url, timeout=120) as response, archive.open("xb") as output:
            shutil.copyfileobj(response, output)
        if sha256(archive) != index[name]["archive_sha256"]:
            raise ValueError("downloaded corpus archive checksum mismatch")
        with tarfile.open(archive) as bundle:
            for member in bundle:
                target = temporary / member.name
                if not target.resolve().is_relative_to(temporary / name):
                    raise ValueError("unsafe corpus archive path")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(member) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                else:
                    raise ValueError("corpus archive must contain only ordinary files/directories")
        (temporary / name).rename(CORPORA / name)


def analyze_run(directory, apps, cases, hierarchies, requests, repetition, timing="precise"):
    import pandas as pd

    engine_names = ["cedar", *[CASES[case].replace("-", "_") for case in cases]]
    summaries = []
    checked = 0
    for app in apps:
        aggregate = pd.read_csv(directory / f"{app}.csv")
        if list(aggregate["num_entities"]) != list(SIZES):
            raise ValueError("unexpected workload sizes")
        for size in SIZES:
            path = directory / f"{app}-{size}-8192-samples.csv"
            samples = pd.read_csv(path)
            expected = hierarchies * requests
            if set(samples["engine"]) != set(engine_names):
                raise ValueError("unexpected engines in raw samples")
            if not (samples["app"] == app).all() or not (samples["num_entities"] == size).all():
                raise ValueError("raw sample workload identity mismatch")
            if samples.duplicated(["hierarchy", "request", "engine"]).any():
                raise ValueError("duplicate request measurements")
            if not ((samples["hierarchy"] >= 1) & (samples["hierarchy"] <= hierarchies)
                    & (samples["request"] >= 0) & (samples["request"] < requests)).all():
                raise ValueError("request identifiers outside corpus bounds")
            if not (samples.groupby("engine").size() == expected).all():
                raise ValueError("missing request measurements")
            if not (samples["errors"] == 0).all() or not (samples["duration_ns"] >= 0).all():
                raise ValueError("authorization error or invalid timing")
            decisions = samples.pivot(index=["hierarchy", "request"], columns="engine",
                                      values="decision")
            if not decisions.isin(["Allow", "Deny"]).all().all():
                raise ValueError("missing or invalid authorization decision")
            if not decisions.eq(decisions["cedar"], axis=0).all().all():
                raise ValueError("authorization decision mismatch")
            row = aggregate.loc[aggregate["num_entities"] == size].iloc[0]
            for engine in engine_names:
                median = row[f"{engine} median_dur_micros"]
                if not math.isfinite(median) or median < 0:
                    raise ValueError("invalid aggregate timing")
                measured = samples.loc[samples["engine"] == engine, "duration_ns"].median() / 1000
                if timing == "precise" and not math.isclose(median, measured, rel_tol=1e-10, abs_tol=1e-10):
                    raise ValueError("aggregate median does not match raw measurements")
            checked += expected
            with path.open("rb") as source, gzip.open(str(path) + ".gz", "xb") as output:
                shutil.copyfileobj(source, output)
            path.unlink()
        cedar = aggregate["cedar median_dur_micros"].mean()
        if cedar <= 0:
            raise ValueError("zero Cedar median: historical timing is too coarse; use precise timing")
        for case in cases:
            engine = CASES[case].replace("-", "_")
            opa = aggregate[f"{engine} median_dur_micros"].mean()
            summaries.append({
                "repetition": repetition, "app": app, "case": case,
                "cedar_average_median_us": cedar, "opa_average_median_us": opa,
                "opa_over_cedar": opa / cedar,
            })
    return summaries, checked


def main():
    parser = argparse.ArgumentParser(description="Replay paired OOPSLA 2024 timing comparisons.")
    preset = parser.add_mutually_exclusive_group()
    preset.add_argument("--smoke", action="store_true", help="2 datastores x 10 requests per size")
    preset.add_argument("--full", action="store_true", help="200 datastores x 500 requests per size (default)")
    parser.add_argument("--app", default=",".join(APPS))
    parser.add_argument("--case", choices=[*CASES, "all"], default="all")
    parser.add_argument("--corpus", help="frozen corpus name; defaults to paper-v1 or smoke-v1")
    parser.add_argument("--generate-corpus", action="store_true",
                        help="explicitly generate a new independent corpus instead of downloading")
    parser.add_argument("--timing", choices=["historical", "precise"], default="precise")
    parser.add_argument("--repetitions", type=int, help="defaults to 3 full or 1 smoke repetitions")
    parser.add_argument("--container", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    apps = args.app.replace("tiny-todo", "tinytodo").split(",")
    if not apps or len(set(apps)) != len(apps) or not set(apps).issubset(APPS):
        parser.error("--app must select github,gdrive,tinytodo without duplicates")
    cases = list(CASES) if args.case == "all" else [args.case]
    repetitions = args.repetitions if args.repetitions is not None else (1 if args.smoke else 3)
    if repetitions < 1:
        parser.error("--repetitions must be positive")
    name = args.corpus or ("smoke-v1" if args.smoke else "paper-v1")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        parser.error("--corpus must be a simple name, not a path")
    mode = "smoke" if args.smoke else "full"
    hierarchies, requests = (2, 10) if args.smoke else (200, 500)
    import matplotlib
    import pandas as pd

    CORPORA.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = RESULTS / f"{timestamp}-{name}-{args.case}-{args.timing}"
    output.mkdir()
    binary = BENCH / "target/release/cedar-benchmarks"
    go_binary = BENCH / "tinytodo/rego/build/bin/tinytodo"
    if args.container:
        binary = Path("/opt/cedar-reproduction/cedar-benchmarks")
        go_binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile("/opt/cedar-reproduction/tinytodo", go_binary)
        go_binary.chmod(0o755)
    else:
        subprocess.run(["cargo", "build", "--release", "--locked", "-j", "4"], cwd=BENCH, check=True)
        subprocess.run(["go", "build", "-mod=readonly", "-o", str(go_binary), "./cmd/tinytodo"],
                       cwd=BENCH / "tinytodo/rego", check=True)
    manifest = {
        "complete": False, "upstream_commit": UPSTREAM, "source_commit": command_output("git", "rev-parse", "HEAD"),
        "working_tree_status": command_output("git", "status", "--porcelain"),
        "preset": mode, "apps": apps, "cases": cases, "sizes": SIZES,
        "num_hierarchies": hierarchies, "num_requests": requests, "repetitions": repetitions,
        "timing": args.timing, "explicit_warmup": False,
        "engine_order": "fixed" if args.timing == "historical" else "rotated across repetitions",
        "cedar_version": "3.0.1", "opa_version": "0.61.0",
        "rust": command_output("rustc", "--version"), "go": command_output("go", "version"),
        "python": platform.python_version(), "matplotlib": matplotlib.__version__, "pandas": pd.__version__,
        "cpu": command_output("lscpu"), "container": args.container,
        "binary_sha256": {"cedar": sha256(binary), "opa": sha256(go_binary)},
        "limits": "container: 4 CPUs / 8 GiB; no dedicated host isolation" if args.container else "native shared host",
        "limitations": "Reconstructed dependency locks/current toolchains, not the paper machine. No explicit warmup. Setup records cover engine construction, OPA compilation, preprocessing and native conversion, not all serialization/IPC/generation costs.",
    }
    tracked = command_output("git", "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    manifest["source_sha256"] = {path: sha256(ROOT / path) for path in tracked if (ROOT / path).is_file()}
    save_json(output / "manifest.json", manifest)
    corpus = CORPORA / name
    parameters = ["--num-hierarchies", hierarchies, "--num-requests", requests,
                  "--num-entities", ",".join(map(str, SIZES))]
    if not corpus.exists():
        if args.generate_corpus:
            print(f"Generating independent {mode} corpus {name} for all three applications.", flush=True)
            run_benchmark(binary, ["--app", "github,gdrive,tiny-todo", "--engine", "cedar",
                                  *parameters, "--record-corpus", corpus,
                                  "--output", output / "generation"], output / "generation.log")
            save_json(corpus / "manifest.json", {
                "format_version": 1, "upstream_commit": UPSTREAM,
                "generator_source_commit": manifest["source_commit"],
                "preset": mode, "apps": APPS, "sizes": SIZES,
                "num_hierarchies": hierarchies, "num_requests": requests,
                "files": corpus_files(corpus),
            })
        else:
            print(f"Downloading frozen corpus {name}.", flush=True)
            download_corpus(name)
    corpus_manifest = verify_corpus(corpus, mode)
    if (corpus_manifest["num_hierarchies"], corpus_manifest["num_requests"]) != (hierarchies, requests):
        raise ValueError("corpus sampling settings mismatch")
    manifest["corpus"] = name
    manifest["corpus_manifest_sha256"] = sha256(corpus / "manifest.json")
    summaries, setup_records, checked = [], [], 0
    for repetition in range(1, repetitions + 1):
        engines = ["cedar", *[CASES[case] for case in cases]]
        if args.timing == "precise":
            offset = (repetition - 1) % len(engines)
            engines = engines[offset:] + engines[:offset]
        run = output / f"run-{repetition}"
        log = output / f"run-{repetition}.log"
        print(f"Running {apps}, {cases}, repetition {repetition}/{repetitions}.", flush=True)
        run_benchmark(binary, ["--app", ",".join(app.replace("tinytodo", "tiny-todo") for app in apps),
                              "--engine", ",".join(engines), *parameters,
                              "--replay-corpus", corpus, "--raw-samples", "--output", run,
                              *(["--precise-timing"] if args.timing == "precise" else [])], log)
        rows, count = analyze_run(run, apps, cases, hierarchies, requests, repetition, args.timing)
        summaries.extend(rows)
        checked += count
        size = None
        for line in log.read_text().splitlines():
            experiment = re.match(r"Running experiment for \S+ with \d+ unstructured bytes and (\d+) entities", line)
            if experiment:
                size = int(experiment[1])
            for prefix in ("opa_setup ", "cedar_setup "):
                if line.startswith(prefix):
                    setup_records.append({"repetition": repetition, "num_entities": size,
                                          **json.loads(line[len(prefix):])})
    per_run = pd.DataFrame(summaries)
    per_run.to_csv(output / "per-repetition.csv", index=False)
    summary = per_run.groupby(["app", "case"], sort=False).agg(
        cedar_average_median_us=("cedar_average_median_us", "mean"),
        opa_average_median_us=("opa_average_median_us", "mean"),
        minimum_run_ratio=("opa_over_cedar", "min"), maximum_run_ratio=("opa_over_cedar", "max"),
    ).reset_index()
    summary["opa_over_cedar"] = summary["opa_average_median_us"] / summary["cedar_average_median_us"]
    summary.to_csv(output / "summary.csv", index=False)
    expected_setup = repetitions * len(apps) * len(SIZES) * hierarchies
    if sum("native_data_policy_ns" in row for row in setup_records) != expected_setup:
        raise ValueError("missing Cedar setup records")
    for case in cases:
        if sum(row.get("case") == case for row in setup_records) != expected_setup:
            raise ValueError(f"missing OPA setup records for {case}")
    pd.DataFrame(setup_records).to_csv(output / "setup.csv", index=False)
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, len(apps), figsize=(4.8 * len(apps), 4), squeeze=False)
    for ax, app in zip(axes[0], apps):
        for engine, label in [("cedar", "Cedar 3.0.1"), *[(CASES[case].replace("-", "_"), case) for case in cases]]:
            frames = [pd.read_csv(output / f"run-{i}/{app}.csv") for i in range(1, repetitions + 1)]
            medians = pd.concat([frame.set_index("num_entities")[f"{engine} median_dur_micros"] for frame in frames], axis=1).mean(axis=1)
            ax.plot(medians.index, medians.values, marker="o", label=label)
        ax.set(title=app, xlabel="Entities per type", ylabel="Authorization time (us)", ylim=(0, None))
        ax.legend(fontsize=8)
    figure.suptitle(f"{mode}: {args.timing} timing; shared corpus {name}")
    figure.tight_layout()
    figure.savefig(output / "comparison.png", dpi=180)
    figure.savefig(output / "comparison.pdf")
    plt.close(figure)
    manifest["validated_workload_requests"] = checked
    manifest["validated_engine_decisions"] = checked * (len(cases) + 1)
    manifest["decision_mismatches"] = 0
    manifest["artifact_sha256"] = {str(path.relative_to(output)): sha256(path)
                                   for path in sorted(output.rglob("*"))
                                   if path.is_file() and path.name != "manifest.json"}
    manifest["complete"] = True
    save_json(output / "manifest.json", manifest)
    print(summary.to_string(index=False))
    print(f"Validated {manifest['validated_engine_decisions']:,} engine decisions. Results: {output}")


if __name__ == "__main__":
    main()
