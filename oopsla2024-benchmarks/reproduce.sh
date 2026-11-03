#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IFS=',' read -r -a comparisons <<< "${BACKENDS:-regorus,regorus-rvm}"
for comparison in "${comparisons[@]}"; do
    output_dir="${OUTPUT_ROOT:-output}/cedar-vs-${comparison}"
    if [[ -e "$output_dir" || -L "$output_dir" ]]; then
        printf 'Refusing to reuse %s; set OUTPUT_ROOT to a new run directory.\n' "$output_dir" >&2
        exit 1
    fi
done

python3 -c 'import matplotlib, pandas'
cargo build --release --locked --package cedar-benchmarks

for comparison in "${comparisons[@]}"; do
    output_dir="${OUTPUT_ROOT:-output}/cedar-vs-${comparison}"
    mkdir -p "$(dirname "$output_dir")"
    mkdir "$output_dir"
    tar -czf "$output_dir/source.tar.gz" \
        Cargo.toml Cargo.lock README.md plot.py reproduce.sh src benches generators
    source_sha256=$(sha256sum "$output_dir/source.tar.gz" | cut -d ' ' -f 1)
    {
        sha256sum Cargo.toml Cargo.lock README.md plot.py reproduce.sh
        find src benches generators -type f -print0 | sort -z | xargs -0 sha256sum
    } > "$output_dir/source-sha256.txt"
    for checkout in cedar-spec cedar-spec/cedar; do
        name="${checkout##*/}"
        git -C "$checkout" diff --binary HEAD > "$output_dir/$name.patch"
        (
            cd "$checkout"
            git ls-files -z --cached --others --exclude-standard |
                while IFS= read -r -d '' source; do
                    if [[ -f "$source" ]]; then
                        sha256sum -- "$source"
                    fi
                done
        ) > "$output_dir/$name-source-sha256.txt"
    done
    command=(
        target/release/cedar-benchmarks bench
        --app "${APPS:-github}"
        --engine "cedar,${comparison}"
        --num-hierarchies "${NUM_HIERARCHIES:-200}"
        --num-requests "${NUM_REQUESTS:-500}"
        --num-entities "${NUM_ENTITIES:-5,10,15,20,30,40,50}"
        --output-dir "$output_dir"
    )
    {
        date --iso-8601=seconds
        printf 'cedar-examples: '
        git rev-parse HEAD
        printf 'cedar-spec: '
        git -C cedar-spec rev-parse HEAD
        git -C cedar-spec status --porcelain --untracked-files=all
        printf 'cedar: '
        git -C cedar-spec/cedar rev-parse HEAD
        git -C cedar-spec/cedar status --porcelain --untracked-files=all
        cargo tree --locked -i regorus
        sha256sum "$output_dir/source.tar.gz" "$output_dir/source-sha256.txt" \
            "$output_dir/cedar-spec-source-sha256.txt" "$output_dir/cedar-source-sha256.txt" \
            target/release/cedar-benchmarks
        printf 'RUSTFLAGS=%s\nCARGO_ENCODED_RUSTFLAGS=%s\n' \
            "${RUSTFLAGS:-}" "${CARGO_ENCODED_RUSTFLAGS:-}"
        rustc --version
        python3 --version
        python3 -c 'import matplotlib, pandas; print("matplotlib", matplotlib.__version__, "pandas", pandas.__version__)'
        lscpu
        printf '\nCommand:'
        printf ' %q' "${command[@]}"
        printf '\n'
    } > "$output_dir/provenance.txt"
    BENCHMARK_SOURCE_SHA256="$source_sha256" MPLBACKEND=Agg "${command[@]}" \
        2>&1 | tee "$output_dir/benchmark.log"
done
