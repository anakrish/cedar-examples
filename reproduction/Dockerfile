FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS go
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" GOMAXPROCS=4 CARGO_BUILD_JOBS=4
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-matplotlib python3-pandas git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY oopsla2024-benchmarks /build/oopsla2024-benchmarks
COPY reproduction/dependencies.py reproduction/versions.json /build/reproduction/
RUN python3 reproduction/dependencies.py
RUN cd oopsla2024-benchmarks && cargo build --release --locked -j 4 \
    && cd rego-harness && go build -mod=readonly -o /opt/cedar-reproduction/opa ./cmd/harness
RUN install /build/oopsla2024-benchmarks/target/release/cedar-benchmarks \
    /opt/cedar-reproduction/cedar-benchmarks
WORKDIR /workspace
